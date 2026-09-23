import json
import textwrap

import pytest

from archscan import query
from archscan.pipeline import analyze


@pytest.fixture
def query_files() -> dict[str, str]:
    return {
        "app/__init__.py": "",
        "app/main.py": textwrap.dedent("""\
            import os
            from app.runner import run
            from app.other import run as other_run

            def main():
                cmd = os.getenv("CMD")
                run(cmd)
                other_run()
            """),
        "app/runner.py": textwrap.dedent("""\
            import subprocess

            def run(cmd):
                subprocess.run(cmd, shell=True)
            """),
        "app/other.py": "def run():\n    return 1\n",
        "app/helper.py": "def helper():\n    return 2\n",
        "lib/__init__.py": "",
        "lib/util.py": "def util():\n    return 3\n",
    }


@pytest.fixture
def analysis(tmp_path, query_files):
    for rel, text in query_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text(
        "from app.main import main\n\ndef test_main():\n    main()\n"
    )
    return analyze(tmp_path, judge=False)


def _assert_json_safe(value) -> None:
    json.dumps(value)


# -- overview -----------------------------------------------------------


def test_overview_has_summary_and_packages(analysis):
    result = query.overview(analysis)

    assert result["summary"]["modules"] == 7
    packages = {p["name"]: p for p in result["packages"]}
    assert packages["app"]["modules"] == 5
    assert packages["lib"]["modules"] == 2
    _assert_json_safe(result)


def test_overview_reports_role_counts_from_judgments(analysis):
    from archscan.judge import Judgment

    analysis.judgments = {
        "app.main": Judgment(role="business_logic", role_confidence=0.9, capabilities={}),
        "app.runner": Judgment(role="business_logic", role_confidence=0.9, capabilities={}),
    }

    result = query.overview(analysis)

    app = next(p for p in result["packages"] if p["name"] == "app")
    assert app["roles"] == {"business_logic": 2}


def test_overview_truncates_packages(analysis):
    result = query.overview(analysis, limit=1)

    assert len(result["packages"]) == 1
    assert result["truncated"] is True
    assert result["total"] == 2


def test_overview_excludes_test_modules(analysis):
    result = query.overview(analysis)

    assert all(p["name"] != "tests" for p in result["packages"])


# -- module ---------------------------------------------------------------


def test_module_returns_entry_with_function_line_and_call_counts(analysis):
    result = query.module(analysis, "app.main")

    assert result["name"] == "app.main"
    functions = {f["name"]: f for f in result["functions"]}
    assert functions["main"]["line"] == 5
    assert functions["main"]["calls"] == 2
    _assert_json_safe(result)


def test_module_unknown_name_suggests_close_matches(analysis):
    result = query.module(analysis, "app.mian")

    assert result["error"] == "unknown module"
    assert "app.main" in result["suggestions"]
    assert len(result["suggestions"]) <= 5


def test_module_truncates_functions(analysis):
    result = query.module(analysis, "app.main", limit=0)

    assert result["functions"] == []
    assert result["truncated"] is True
    assert result["total"] == 1


def test_module_excludes_test_modules(analysis):
    result = query.module(analysis, "tests")

    assert result["error"] == "unknown module"


# -- callers / callees ------------------------------------------------------


def test_callees_resolves_unique_suffix(analysis):
    result = query.callees(analysis, "runner.run")

    assert result["function"] == "app.runner.run"


def test_callees_full_qualname(analysis):
    result = query.callees(analysis, "app.main.main")

    names = {c["function"] for c in result["callees"]}
    assert names == {"app.runner.run", "app.other.run"}
    assert all(c["certain"] for c in result["callees"])
    _assert_json_safe(result)


def test_callers_ambiguous_suffix(analysis):
    result = query.callers(analysis, "run")

    assert result["error"] == "ambiguous"
    assert set(result["matches"]) == {"app.runner.run", "app.other.run"}


def test_callers_unknown_suffix_suggests_close_matches(analysis):
    result = query.callers(analysis, "runenr.run")

    assert result["error"] == "unknown function"
    assert "suggestions" in result


def test_callers_of_run_is_main(analysis):
    result = query.callers(analysis, "app.runner.run")

    assert result["callers"] == [{"function": "app.main.main", "certain": True}]


def test_callees_truncates(analysis):
    result = query.callees(analysis, "app.main.main", limit=1)

    assert len(result["callees"]) == 1
    assert result["truncated"] is True
    assert result["total"] == 2


# -- trace ------------------------------------------------------------------


def test_trace_env_has_finding_and_path(analysis):
    result = query.trace(analysis, "env")

    finding = next(f for f in result["findings"] if f["sink_call"] == "subprocess.run")
    assert finding["path"] == ["app.main.main", "app.runner.run"]
    _assert_json_safe(result)


def test_trace_unknown_kind_lists_kinds(analysis):
    result = query.trace(analysis, "bogus")

    assert result["error"] == "unknown kind"
    assert "env" in result["kinds"]


def test_trace_kind_with_nothing_reached_is_empty(analysis):
    result = query.trace(analysis, "database")

    assert result["modules"] == []
    assert result["findings"] == []


def test_trace_excludes_test_modules(analysis):
    result = query.trace(analysis, "env")

    names = {m["name"] for m in result["modules"]}
    assert all(not n.startswith("tests") for n in names)


# -- path_between -------------------------------------------------------


def test_path_between_prefers_certain_path(analysis):
    calls = analysis.project.calls
    calls.add_edge("app.main.main", "app.helper.helper", guess=False)
    calls.add_edge("app.helper.helper", "lib.util.util", guess=False)
    calls.add_edge("app.main.main", "lib.util.util", guess=True)

    result = query.path_between(analysis, "app.main.main", "lib.util.util")

    assert result["path"] == ["app.main.main", "app.helper.helper", "lib.util.util"]
    assert result["certain"] is True


def test_path_between_falls_back_to_guessed_path(analysis):
    calls = analysis.project.calls
    calls.add_edge("app.main.main", "lib.util.util", guess=True)

    result = query.path_between(analysis, "app.main.main", "lib.util.util")

    assert result["path"] == ["app.main.main", "lib.util.util"]
    assert result["certain"] is False


def test_path_between_no_path_returns_null(analysis):
    result = query.path_between(analysis, "app.helper.helper", "app.runner.run")

    assert result == {"path": None}


def test_path_between_unknown_source_names_the_argument(analysis):
    result = query.path_between(analysis, "app.mian.main", "app.runner.run")

    assert result["error"] == "unknown function"
    assert result["argument"] == "source"
    assert "suggestions" in result


def test_path_between_ambiguous_target_names_the_argument(analysis):
    result = query.path_between(analysis, "app.main.main", "run")

    assert result["error"] == "ambiguous"
    assert result["argument"] == "target"
    assert set(result["matches"]) == {"app.runner.run", "app.other.run"}


# -- search -------------------------------------------------------------


def test_search_matches_modules_and_functions_case_insensitively(analysis):
    result = query.search(analysis, "RUN")

    assert "app.runner" in result["modules"]
    assert "app.runner.run" in result["functions"]
    assert "app.other.run" in result["functions"]
    _assert_json_safe(result)


def test_search_excludes_test_modules(analysis):
    result = query.search(analysis, "main")

    assert all(not n.startswith("tests") for n in result["modules"])
    assert all(not n.startswith("tests") for n in result["functions"])


def test_search_truncates_each_list_independently(analysis):
    result = query.search(analysis, "run", limit=1)

    assert len(result["functions"]) == 1
    assert result["functions_truncated"] is True
    assert result["functions_total"] == 2
    assert "modules_truncated" not in result


# -- json safety across all functions ----------------------------------


def test_every_query_function_result_is_json_safe(analysis):
    _assert_json_safe(query.overview(analysis))
    _assert_json_safe(query.module(analysis, "app.main"))
    _assert_json_safe(query.module(analysis, "does.not.exist"))
    _assert_json_safe(query.callers(analysis, "app.runner.run"))
    _assert_json_safe(query.callers(analysis, "run"))
    _assert_json_safe(query.callees(analysis, "app.main.main"))
    _assert_json_safe(query.trace(analysis, "env"))
    _assert_json_safe(query.trace(analysis, "bogus"))
    _assert_json_safe(query.path_between(analysis, "app.main.main", "app.runner.run"))
    _assert_json_safe(query.path_between(analysis, "app.helper.helper", "app.runner.run"))
    _assert_json_safe(query.search(analysis, "run"))

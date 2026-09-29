from pathlib import Path
from textwrap import dedent

import pytest

from archscan.callgraph import build_call_graph
from archscan.catalog import load_catalog
from archscan.coverage import compute_coverage
from archscan.report import render, render_html
from archscan.scan.python import is_test_path
from archscan.trace import trace


@pytest.mark.parametrize(
    "path, expected",
    [
        ("tests/x.py", True),
        ("pkg/test_a.py", True),
        ("pkg/a_test.py", True),
        ("conftest.py", True),
        ("pkg/test/x.py", True),
        ("pkg/contest.py", False),
        ("latest/a.py", False),
        ("testing/x.py", False),
        ("mypkg/tests_data.py", False),
        ("src/pkg/tests/x.py", True),
    ],
)
def test_is_test_path(path, expected):
    assert is_test_path(Path(path)) is expected


FILES = {
    "app/__init__.py": "",
    "app/a.py": "def f():\n    return 1\n\ndef g():\n    return 2\n",
    "app/guessed.py": "class Box:\n    def open_it(self):\n        return 1\n",
    "app/imported.py": "def h():\n    return 1\n",
    "app/empty.py": "",
    "app/untouched.py": "def z():\n    return 1\n",
    "tests/__init__.py": "",
    "tests/test_a.py": dedent("""\
        from app.a import f
        from app import imported, empty

        def test_f():
            f()

        def test_guess(obj):
            obj.open_it()
        """),
}


@pytest.fixture
def full(build):
    project = build(FILES)
    build_call_graph(project)
    return project


def test_without_tests_drops_test_modules_and_functions(full):
    kept = full.without_tests()
    assert not any(m.is_test for m in kept.modules())
    assert not kept.has_module("tests.test_a")
    assert not any(f.module.startswith("tests") for f in kept.functions())
    assert kept.has_function("app.a.f")
    assert not any(t.startswith("tests") for edge in kept.graph.edges for t in edge)
    assert kept.root == full.root
    assert len(kept.calls) == 0


def test_statuses(full):
    coverage = compute_coverage(full)
    by_name = {m.name: m for m in coverage.modules}
    assert "tests.test_a" not in by_name
    assert by_name["app.a"].status == "covered"
    assert (by_name["app.a"].covered, by_name["app.a"].total) == (1, 2)
    assert by_name["app.a"].uncovered == ["app.a.g"]
    assert by_name["app.guessed"].status == "maybe"
    assert by_name["app.imported"].status == "imported only"
    assert by_name["app.untouched"].status == "not covered"
    assert "app" not in by_name
    assert by_name["app.empty"].status == "imported only"
    assert coverage.counts() == {"not covered": 1, "maybe": 1, "imported only": 2, "covered": 1}


def test_no_tests_gives_none(build, flow_files):
    project = build(flow_files)
    build_call_graph(project)
    assert compute_coverage(project) is None


def test_reports_show_coverage(full):
    coverage = compute_coverage(full)
    project = full.without_tests()
    build_call_graph(project)
    html = render_html(project, {}, {}, None, coverage=coverage)
    assert 'data-tab="coverage"' in html and "Coverage</button>" in html
    assert "imported only" in html and "app.untouched" in html
    panel = html[html.index('id="coverage"'):]
    assert panel.index("app.untouched") < panel.index("app.a</code>")
    md = render(project, {}, {}, None, coverage=coverage)
    assert "## Test coverage" in md
    assert "- `app.a` — covered (1/2)" in md
    assert "- `app.untouched` — not covered (0/1)" in md
    assert 'data-tab="coverage"' not in render_html(project, {}, {})
    assert "## Test coverage" not in render(project, {}, {})


def test_reports_and_trace_skip_tests(build, flow_files):
    files = dict(flow_files)
    files["tests/test_main.py"] = "import os\nimport pytest\n\ndef test_x():\n    os.getenv('A')\n"
    full = build(files)
    project = full.without_tests()
    build_call_graph(project)
    result = trace(project, load_catalog())
    html = render_html(project, {}, {}, result)
    md = render(project, {}, {}, result)
    for text in (html, md):
        assert "tests.test_main" not in text
        assert "pytest" not in text


def test_html_escapes_module_names():
    from archscan.coverage import Coverage, ModuleCoverage, coverage_tab

    tab = coverage_tab(Coverage([ModuleCoverage("a&b<c", "covered", 1, 1, [])]))
    assert "a&amp;b&lt;c" in tab[2]
    assert "a&b<c" not in tab[2]

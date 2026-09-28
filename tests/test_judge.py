import threading
from types import SimpleNamespace

import pytest
from typesafe_sdk import Choice

from archscan import judge
from archscan.capabilities import derive_capabilities
from archscan.catalog import load_catalog
from archscan.judge import judge_project

IN_TOKENS, OUT_TOKENS = 100, 10


class FakeClient:
    calls: list[dict] = []
    models: list[str] = []
    fail_for: set[str] = set()
    lock = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def system_one(self, state, questions, model):
        with FakeClient.lock:
            FakeClient.calls.append({"state": state, "questions": questions, "model": model})
        if state["module"] in FakeClient.fail_for:
            raise RuntimeError("boom")
        return SimpleNamespace(
            choices={"role": SimpleNamespace(choice="utility", confidence=0.9)},
            nouls={"handles_auth": SimpleNamespace(noul=0.7)},
            usage=SimpleNamespace(input_tokens=IN_TOKENS, output_tokens=OUT_TOKENS),
        )


@pytest.fixture(autouse=True)
def fake(monkeypatch, tmp_path):
    FakeClient.calls = []
    FakeClient.fail_for = set()
    monkeypatch.setattr(judge, "TypeSafeClient", FakeClient)
    monkeypatch.setenv("ARCHSCAN_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("ARCHSCAN_CACHE", raising=False)
    return FakeClient


@pytest.fixture
def catalog():
    return load_catalog()


def run(project, model=judge.DEFAULT_MODEL):
    return judge_project(project, model)


def test_empty_modules_are_not_sent(build, fake):
    project = build(
        {
            "empty.py": '"""Doc."""\n# comment\n',
            "imports.py": "import os\nfrom sys import path\n__all__ = ['os']\n",
            "real.py": "def f():\n    return 1\n",
        }
    )
    judgments, usage = run(project)
    assert [c["state"]["module"] for c in fake.calls] == ["real"]
    for name in ("empty", "imports"):
        assert judgments[name].role == "package"
        assert judgments[name].handles_auth == 0.0
    assert usage.calls == 1


def test_class_only_module_is_not_empty(build, fake):
    project = build({"models.py": "class A:\n    x = 1\n"})
    judgments, _ = run(project)
    assert len(fake.calls) == 1
    assert judgments["models"].role == "utility"


def test_module_level_code_is_not_empty(build, fake):
    build_project = build({"script.py": "print('hi')\n"})
    run(build_project)
    assert len(fake.calls) == 1


def test_request_contains_only_role_and_handles_auth(build, fake):
    project = build({"a.py": "def f():\n    return 1\n"})
    judgments, _ = run(project)
    assert set(fake.calls[0]["questions"]) == {"role", "handles_auth"}
    assert judgments["a"].handles_auth == 0.7


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import os\ndef f():\n    return os.getenv('K')\n", {"reads_secrets"}),
        ("import requests\ndef f():\n    return requests.get('u')\n", {"touches_network"}),
        ("def f(cursor):\n    cursor.execute('select 1')\n", {"touches_db"}),
        ("import sys\ndef f():\n    return sys.argv\n", {"reads_user_input"}),
        ("def f():\n    return input()\n", {"reads_user_input"}),
        ("@app.get('/x')\ndef f():\n    return 1\n", {"reads_user_input"}),
        ("def f():\n    return 1\n", set()),
    ],
)
def test_derived_capabilities(build, catalog, source, expected):
    project = build({"m.py": source})
    caps = derive_capabilities(project, catalog, "m")
    assert set(caps) == expected


def test_second_run_uses_cache(build, fake):
    project = build({"a.py": "def a():\n    return 1\n", "b.py": "def b():\n    return 2\n"})
    first, usage1 = run(project)
    assert len(fake.calls) == 2 and usage1.calls == 2
    second, usage2 = run(project)
    assert len(fake.calls) == 2
    assert usage2 == judge.TokenUsage()
    assert second == first


def test_changed_source_causes_one_call(build, fake):
    project = build({"a.py": "def a():\n    return 1\n", "b.py": "def b():\n    return 2\n"})
    run(project)
    (project.root / "b.py").write_text("def b():\n    return 3\n")
    run(project)
    assert len(fake.calls) == 3
    assert fake.calls[-1]["state"]["module"] == "b"


def test_changed_model_calls_again(build, fake):
    project = build({"a.py": "def a():\n    return 1\n"})
    run(project, "m1")
    run(project, "m1")
    assert len(fake.calls) == 1
    run(project, "m2")
    assert len(fake.calls) == 2
    assert fake.calls[-1]["model"] == "m2"


def test_changed_questions_invalidate(build, fake, monkeypatch):
    project = build({"a.py": "def a():\n    return 1\n"})
    run(project)
    changed = {**judge.QUESTIONS, "role": Choice(instructions="Other?", criteria={"x": None})}
    monkeypatch.setattr(judge, "QUESTIONS", changed)
    run(project)
    assert len(fake.calls) == 2


def test_corrupt_cache_is_ignored_and_rewritten(build, fake, tmp_path):
    project = build({"a.py": "def a():\n    return 1\n"})
    cache_file = tmp_path / "cache" / "judgments.json"
    cache_file.parent.mkdir()
    cache_file.write_text("{not json")
    run(project)
    assert len(fake.calls) == 1
    run(project)
    assert len(fake.calls) == 1
    assert cache_file.read_text().startswith("{")
    assert list(cache_file.parent.glob("*.tmp")) == []


def test_cache_disabled(build, fake, monkeypatch, tmp_path):
    monkeypatch.setenv("ARCHSCAN_CACHE", "0")
    project = build({"a.py": "def a():\n    return 1\n"})
    run(project)
    run(project)
    assert len(fake.calls) == 2
    assert not (tmp_path / "cache" / "judgments.json").exists()


def test_cache_write_failure_does_not_fail(build, fake, monkeypatch, tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("file")
    monkeypatch.setenv("ARCHSCAN_CACHE_DIR", str(blocker))
    project = build({"a.py": "def a():\n    return 1\n"})
    judgments, _ = run(project)
    assert judgments["a"].role == "utility"


def test_parallel_order_and_usage(build, fake):
    project = build({f"m{i:02d}.py": f"def f{i}():\n    return {i}\n" for i in range(10)})
    judgments, usage = run(project)
    assert list(judgments) == [m.name for m in project.modules()]
    assert len(fake.calls) == 10
    assert usage.calls == 10
    assert usage.input_tokens == 10 * IN_TOKENS
    assert usage.output_tokens == 10 * OUT_TOKENS


def test_parse_failure_after_successful_call_still_counts_tokens(build, monkeypatch):
    class BadResponse:
        choices: dict = {}
        nouls: dict = {}
        usage = SimpleNamespace(input_tokens=IN_TOKENS, output_tokens=OUT_TOKENS)

    class BadClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def system_one(self, state, questions, model):
            return BadResponse()

    monkeypatch.setattr(judge, "TypeSafeClient", BadClient)
    project = build({"a.py": "def a():\n    return 1\n"})

    judgments, usage = run(project)

    assert judgments["a"].role == "unknown"
    assert usage.calls == 1
    assert usage.input_tokens == IN_TOKENS
    assert usage.output_tokens == OUT_TOKENS


def test_failure_gives_unknown_and_is_not_cached(build, fake):
    project = build(
        {
            "bad.py": "import os\ndef f():\n    return os.getenv('K')\n",
            "good.py": "def g():\n    return 1\n",
        }
    )
    fake.fail_for = {"bad"}
    judgments, usage = run(project)
    assert judgments["bad"].role == "unknown"
    assert judgments["bad"].handles_auth == 0.0
    assert judgments["good"].role == "utility"
    assert usage.calls == 1
    fake.fail_for = set()
    fake.calls.clear()
    judgments, _ = run(project)
    assert [c["state"]["module"] for c in fake.calls] == ["bad"]
    assert judgments["bad"].role == "utility"

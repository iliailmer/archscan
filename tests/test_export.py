import json
import sys

from archscan.cli import main
from archscan.export import SCHEMA_VERSION, to_json
from archscan.judge import Judgment
from archscan.pipeline import analyze

TOP_LEVEL_KEYS = {"schema", "root", "summary", "modules", "functions", "traces", "coverage"}


def test_top_level_keys_are_exact(tmp_path, flow_files):
    for rel, text in flow_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    analysis = analyze(tmp_path, judge=False)

    data = to_json(analysis)

    assert set(data.keys()) == TOP_LEVEL_KEYS
    assert data["schema"] == SCHEMA_VERSION == 1


def test_env_finding_appears_with_its_path(tmp_path, flow_files):
    for rel, text in flow_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    analysis = analyze(tmp_path, judge=False)

    data = to_json(analysis)

    env = next(t for t in data["traces"] if t["kind"] == "env")
    finding = next(f for f in env["findings"] if f["sink_call"] == "subprocess.run")
    assert finding["path"] == ["app.main.main", "app.runner.run"]
    assert finding["function"] == "app.runner.run"
    assert finding["certain"] is True


def test_no_tests_module_anywhere(tmp_path, flow_files):
    for rel, text in flow_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text(
        "from app.main import main\n\ndef test_main():\n    main()\n"
    )
    analysis = analyze(tmp_path, judge=False)

    data = to_json(analysis)

    for module in data["modules"]:
        assert not module["name"].startswith("tests.")
        assert module["name"] != "tests"
    for fn in data["functions"]:
        assert not fn["module"].startswith("tests.")
        assert not fn["qualname"].startswith("tests.")


def test_role_is_none_without_judgments(tmp_path, flow_files):
    for rel, text in flow_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    analysis = analyze(tmp_path, judge=False)

    data = to_json(analysis)

    main_module = next(m for m in data["modules"] if m["name"] == "app.main")
    assert main_module["role"] is None
    assert main_module["capabilities"] == []


def test_role_is_set_when_a_judgment_is_passed_in(tmp_path, flow_files):
    for rel, text in flow_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    analysis = analyze(tmp_path, judge=False)
    analysis.judgments = {
        "app.main": Judgment(
            role="business_logic",
            role_confidence=0.9,
            capabilities={"reads_secrets": 0.9, "handles_auth": 0.1},
        )
    }

    data = to_json(analysis)

    main_module = next(m for m in data["modules"] if m["name"] == "app.main")
    assert main_module["role"] == "business_logic"
    assert main_module["capabilities"] == ["reads_secrets"]


def test_cli_writes_a_valid_json_file_for_dash_o(tmp_path, flow_files, monkeypatch):
    for rel, text in flow_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    out = tmp_path / "out.json"
    monkeypatch.setattr(sys, "argv", ["archscan", str(tmp_path), "-o", str(out)])
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr("archscan.cli.load_dotenv", lambda: None)

    main()

    data = json.loads(out.read_text())
    assert set(data.keys()) == TOP_LEVEL_KEYS


def test_output_is_deterministic(tmp_path, flow_files):
    for rel, text in flow_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    analysis = analyze(tmp_path, judge=False)

    first = json.dumps(to_json(analysis), indent=1)
    second = json.dumps(to_json(analysis), indent=1)

    assert first == second

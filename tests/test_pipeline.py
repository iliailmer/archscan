import pytest

from archscan.pipeline import analyze


def _write(tmp_path, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def test_analyze_returns_project_without_test_modules_and_env_trace(tmp_path, flow_files):
    _write(tmp_path, flow_files)
    _write(tmp_path, {"tests/test_app.py": "def test_x():\n    pass\n"})
    analysis = analyze(tmp_path, judge=False)

    assert "tests.test_app" in {m.name for m in analysis.full.modules()}
    assert "tests.test_app" not in {m.name for m in analysis.project.modules()}
    assert analysis.judgments == {}
    assert "env" in analysis.result.traces
    findings = analysis.result.traces["env"].findings
    assert any(f.sink_call == "subprocess.run" for f in findings)


def test_analyze_unknown_kind_raises_value_error(tmp_path, flow_files):
    _write(tmp_path, flow_files)
    with pytest.raises(ValueError, match="Unknown trace kind"):
        analyze(tmp_path, only="bogus")


def test_analyze_bad_archscan_toml_raises_value_error(tmp_path, flow_files):
    _write(tmp_path, flow_files)
    (tmp_path / "archscan.toml").write_text("[scan\n")
    with pytest.raises(ValueError, match=r"^Invalid archscan\.toml:"):
        analyze(tmp_path)


def test_analyze_bad_root_raises_not_a_directory_error(tmp_path):
    with pytest.raises(NotADirectoryError):
        analyze(tmp_path / "missing")

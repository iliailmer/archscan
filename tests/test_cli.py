import sys

import pytest

from archscan.cli import main


def test_unknown_trace_kind_exits_with_valid_kinds(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["archscan", str(tmp_path), "--trace", "bogus"])
    with pytest.raises(SystemExit) as info:
        main()
    message = str(info.value)
    assert "bogus" in message
    assert "env" in message


def _run(tmp_path, monkeypatch, capsys, files):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    monkeypatch.setattr(sys, "argv", ["archscan", str(tmp_path), "-o", str(tmp_path / "out.md")])
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr("archscan.cli.load_dotenv", lambda: None)
    main()
    return capsys.readouterr().err


def test_log_reports_skipped_directories_but_not_hidden_ones(tmp_path, monkeypatch, capsys):
    log = _run(tmp_path, monkeypatch, capsys, {".venv/x.py": "", "docs/y.py": "", "keep.py": ""})
    assert "Skipped 1 files in: docs" in log
    assert ".venv" not in log


def test_log_has_no_skipped_line_when_only_hidden_dirs_are_skipped(tmp_path, monkeypatch, capsys):
    log = _run(tmp_path, monkeypatch, capsys, {".venv/x.py": "", "keep.py": ""})
    assert "Skipped" not in log
    assert "Scanned 1 modules, 0 dependencies" in log


@pytest.mark.parametrize("content", ["[scan\n", 'scan = "x"\n', '[scan]\nskip = "docs"\n', "[scan]\nskip = 5\n"])
def test_bad_settings_file_exits_with_message(tmp_path, monkeypatch, content):
    (tmp_path / "archscan.toml").write_text(content)
    monkeypatch.setattr(sys, "argv", ["archscan", str(tmp_path)])
    with pytest.raises(SystemExit) as info:
        main()
    assert str(info.value).startswith("Invalid archscan.toml:")


def test_bad_sources_toml_exits_with_message(tmp_path, monkeypatch):
    (tmp_path / "sources.toml").write_text('[[source]]\nmatch = ["x"]\n')
    monkeypatch.setattr(sys, "argv", ["archscan", str(tmp_path)])
    with pytest.raises(SystemExit) as info:
        main()
    assert str(info.value).startswith("Invalid sources.toml:")


def test_without_with_jev_no_typesafe_client_is_created(tmp_path, monkeypatch, capsys):
    from archscan import judge

    def boom():
        raise AssertionError("TypeSafeClient should not be created without --with-jev")

    monkeypatch.setattr(judge, "TypeSafeClient", boom)
    _run(tmp_path, monkeypatch, capsys, {"a.py": "def f():\n    return 1\n"})


def test_with_jev_without_api_key_exits_with_message(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    monkeypatch.setattr(sys, "argv", ["archscan", str(tmp_path), "--with-jev"])
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr("archscan.cli.load_dotenv", lambda: None)
    with pytest.raises(SystemExit) as info:
        main()
    assert str(info.value) == "--with-jev needs TYPESAFE_API_KEY"

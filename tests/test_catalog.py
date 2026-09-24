import pytest

from archscan.catalog import load_catalog


def test_default_sources_and_sinks():
    catalog = load_catalog()
    assert catalog.source_kinds("os.getenv") == ["env"]
    assert catalog.source_kinds("sys.argv") == ["cli"]
    assert "file" in catalog.source_kinds("open")
    assert catalog.source_kinds("json.loads") == []
    assert catalog.sink_kinds("subprocess.run") == ["process"]
    assert catalog.sink_kinds("eval") == ["process"]
    assert catalog.decorator_kinds("app.get") == ["network"]
    assert catalog.decorator_kinds("click.command") == ["cli"]
    assert {"cli", "env", "file", "network", "database"} <= set(catalog.kinds())


def test_bad_sources_toml_syntax_names_the_file(tmp_path):
    (tmp_path / "sources.toml").write_text("[[source\n")
    with pytest.raises(ValueError, match=r"^Invalid sources\.toml:"):
        load_catalog(tmp_path)


def test_sources_toml_entry_missing_kind_raises_value_error(tmp_path):
    (tmp_path / "sources.toml").write_text('[[source]]\nmatch = ["x"]\n')
    with pytest.raises(ValueError, match=r"^Invalid sources\.toml:"):
        load_catalog(tmp_path)


def test_project_file_extends_the_defaults(tmp_path):
    (tmp_path / "sources.toml").write_text(
        '[[source]]\nkind = "queue"\nmatch = ["mq.recv"]\n\n[[sink]]\nkind = "queue"\nmatch = ["mq.send"]\n'
    )
    catalog = load_catalog(tmp_path)
    assert "queue" in catalog.source_kinds("mq.recv")
    assert "queue" in catalog.sink_kinds("mq.send")
    assert catalog.source_kinds("os.getenv") == ["env"]

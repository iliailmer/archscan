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


def test_project_file_extends_the_defaults(tmp_path):
    (tmp_path / "sources.toml").write_text(
        '[[source]]\nkind = "queue"\nmatch = ["mq.recv"]\n\n[[sink]]\nkind = "queue"\nmatch = ["mq.send"]\n'
    )
    catalog = load_catalog(tmp_path)
    assert "queue" in catalog.source_kinds("mq.recv")
    assert "queue" in catalog.sink_kinds("mq.send")
    assert catalog.source_kinds("os.getenv") == ["env"]

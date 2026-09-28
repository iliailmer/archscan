import asyncio
import json
import os
import time

import pytest

from archscan import mcp_server


@pytest.fixture(autouse=True)
def no_typesafe(monkeypatch):
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def clear_cache():
    mcp_server._cache.clear()
    yield
    mcp_server._cache.clear()


@pytest.fixture
def repo(tmp_path, flow_files):
    for rel, text in flow_files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp_path


def test_overview_returns_query_result(repo):
    result = mcp_server.overview(str(repo))

    assert result["summary"]["modules"] == 4
    assert any(p["name"] == "app" for p in result["packages"])


def test_module_returns_entry(repo):
    result = mcp_server.module(str(repo), "app.main")

    assert result["name"] == "app.main"
    assert any(f["name"] == "main" for f in result["functions"])


def test_trace_returns_env_finding(repo):
    result = mcp_server.trace(str(repo), "env")

    assert result["kind"] == "env"
    assert any(f["sink_call"] == "subprocess.run" for f in result["findings"])


def test_callers_resolves_unique_suffix(repo):
    result = mcp_server.callers(str(repo), "runner.run")

    assert result["function"] == "app.runner.run"


def test_callees_resolves_unique_suffix(repo):
    result = mcp_server.callees(str(repo), "main.main")

    assert result["function"] == "app.main.main"


def test_path_between_returns_path(repo):
    result = mcp_server.path_between(str(repo), "app.main.main", "app.runner.run")

    assert result["path"] == ["app.main.main", "app.runner.run"]


def test_search_matches_case_insensitively(repo):
    result = mcp_server.search(str(repo), "RUN")

    assert "app.runner" in result["modules"]


def test_bad_path_returns_error():
    result = mcp_server.overview("/no/such/path/archscan-test-xyz")

    assert result == {"error": "Not a directory: /no/such/path/archscan-test-xyz"}


def test_bad_archscan_toml_returns_error(repo):
    (repo / "archscan.toml").write_text("[scan\n")

    result = mcp_server.overview(str(repo))

    assert "error" in result
    assert "archscan.toml" in result["error"]


def test_cache_returns_same_analysis_object(repo):
    first = mcp_server._analysis_for(str(repo))
    second = mcp_server._analysis_for(str(repo))

    assert first is second


def test_cache_rescans_after_rename(repo):
    mcp_server._analysis_for(str(repo))

    (repo / "app" / "other.py").rename(repo / "app" / "renamed.py")

    renamed = mcp_server.module(str(repo), "app.renamed")
    old = mcp_server.module(str(repo), "app.other")
    assert renamed.get("name") == "app.renamed"
    assert old.get("error") == "unknown module"


def test_cache_rescans_after_file_touch(repo):
    first = mcp_server._analysis_for(str(repo))

    target = repo / "app" / "other.py"
    future = time.time() + 100
    os.utime(target, (future, future))

    second = mcp_server._analysis_for(str(repo))

    assert second is not first


# -- in-process client/server round trip -------------------------------

try:
    import mcp.shared.memory as _memory

    _HAS_MEMORY_HELPER = hasattr(_memory, "create_connected_server_and_client_session")
except ImportError:
    _memory = None
    _HAS_MEMORY_HELPER = False


async def _round_trip(repo_path: str):
    async with _memory.create_connected_server_and_client_session(mcp_server.server._mcp_server) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools.tools}
        result = await client.call_tool("overview", {"path": repo_path})
        return names, result


@pytest.mark.skipif(
    not _HAS_MEMORY_HELPER,
    reason="mcp.shared.memory.create_connected_server_and_client_session not available in installed SDK",
)
def test_round_trip_lists_tools_and_calls_overview(repo):
    names, result = asyncio.run(_round_trip(str(repo)))

    assert names == {"overview", "module", "callers", "callees", "trace", "path_between", "search"}
    assert result.isError is False
    payload = json.loads(result.content[0].text)
    assert payload["summary"]["modules"] == 4


def _later(path):
    stamp = time.time() + 100
    os.utime(path, (stamp, stamp))


def test_sources_toml_edits_trigger_a_rescan(repo):
    assert mcp_server.trace(str(repo), "env")["kind"] == "env"

    sources = repo / "sources.toml"
    sources.write_text('[[source]]\nkind = "custom_src"\nmatch = ["mylib.read"]\n')
    _later(sources)
    assert mcp_server.trace(str(repo), "custom_src").get("kind") == "custom_src"

    sources.unlink()
    assert mcp_server.trace(str(repo), "custom_src")["error"] == "unknown kind"


def test_archscan_toml_edits_trigger_a_rescan(repo):
    (repo / "extra").mkdir()
    (repo / "extra" / "x.py").write_text("def helper():\n    return 1\n")
    assert "extra.x" in json.dumps(mcp_server.search(str(repo), "extra"))

    settings = repo / "archscan.toml"
    settings.write_text('[scan]\nskip = ["extra"]\n')
    _later(settings)
    assert "extra.x" not in json.dumps(mcp_server.search(str(repo), "extra"))


def test_bad_sources_toml_returns_error(repo):
    (repo / "sources.toml").write_text('[[source]]\nmatch = ["x"]\n')

    result = mcp_server.overview(str(repo))

    assert result["error"].startswith("Invalid sources.toml:")


def test_unexpected_analysis_error_returns_error_dict(repo, monkeypatch):
    def boom(root, judge=False):
        raise RuntimeError("boom")

    monkeypatch.setattr(mcp_server, "analyze", boom)

    assert mcp_server.overview(str(repo)) == {"error": "analysis failed: RuntimeError: boom"}


def test_with_jev_env_without_api_key_skips_jev_and_warns_once(repo, monkeypatch):
    from loguru import logger

    from archscan import pipeline

    def unreachable(*args, **kwargs):
        raise AssertionError("judge_project should not be called without TYPESAFE_API_KEY")

    monkeypatch.setenv("ARCHSCAN_WITH_JEV", "1")
    monkeypatch.setattr(pipeline, "judge_project", unreachable)

    messages: list[str] = []
    sink_id = logger.add(messages.append, level="WARNING", format="{message}")
    try:
        result = mcp_server.module(str(repo), "app.main")
    finally:
        logger.remove(sink_id)

    assert result["role"] is None
    assert sum(1 for m in messages if "ARCHSCAN_WITH_JEV=1 needs TYPESAFE_API_KEY" in m) == 1

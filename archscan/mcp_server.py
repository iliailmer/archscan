import os
import sys
import threading
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger
from mcp.server.fastmcp import FastMCP

from archscan import query
from archscan.pipeline import Analysis, analyze
from archscan.settings import load_scan_settings

server = FastMCP("archscan")

Signature = tuple[int, float, float | None, float | None]

_cache: dict[Path, tuple[Signature, Analysis]] = {}
_lock = threading.Lock()

_CONFIG_FILES = ("archscan.toml", "sources.toml")


def _config_mtime(root: Path, name: str) -> float | None:
    path = root / name
    return path.stat().st_mtime if path.is_file() else None


def _signature(root: Path, skip: set[str]) -> Signature:
    """Count `.py` files not skipped by the scan, the newest mtime among them,
    and the mtimes of `archscan.toml`/`sources.toml` (None when absent), so
    editing either config file also triggers a rescan.
    """
    count = 0
    newest = 0.0
    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        if any(part in skip for part in rel.parts):
            continue
        count += 1
        newest = max(newest, path.stat().st_mtime)
    configs = tuple(_config_mtime(root, name) for name in _CONFIG_FILES)
    return (count, newest, *configs)


def _analysis_for(path: str) -> Analysis | dict:
    """Return the cached `Analysis` for `path`, rescanning if the repo changed."""
    root = Path(path).resolve()
    if not root.is_dir():
        return {"error": f"Not a directory: {root}"}
    try:
        skip = load_scan_settings(root)
    except ValueError as error:
        return {"error": f"Invalid archscan.toml: {error}"}

    signature = _signature(root, skip)
    with _lock:
        cached = _cache.get(root)
    if cached and cached[0] == signature:
        return cached[1]

    try:
        analysis = analyze(root)
    except (ValueError, NotADirectoryError) as error:
        return {"error": str(error)}
    except Exception as error:
        logger.exception("Analysis failed for {}", root)
        return {"error": f"analysis failed: {type(error).__name__}: {error}"}

    with _lock:
        _cache[root] = (signature, analysis)
    return analysis


@server.tool()
def overview(path: str, limit: int = query.DEFAULT_LIMIT) -> dict:
    """Summarize a Python repository: module/function counts and a per-package
    breakdown with detected roles (from AI classification, when enabled).

    Use this first to get oriented in an unfamiliar repo. `path` is the
    repository's root directory. The `packages` list is capped at `limit`
    (default 50); when cut, `truncated` is true and `total` gives the full count.
    """
    analysis = _analysis_for(path)
    if isinstance(analysis, dict):
        return analysis
    return query.overview(analysis, limit=limit)


@server.tool()
def module(path: str, name: str, limit: int = query.DEFAULT_LIMIT) -> dict:
    """Look up one module: its role, capabilities, risks, imports/imported-by,
    and its functions with line numbers and outgoing call counts.

    `name` is the dotted module name (e.g. "app.main"). Unknown names return
    an error with close-match suggestions. The `functions` list is capped at
    `limit` (default 50); when cut, `truncated` is true and `total` gives the
    full count.
    """
    analysis = _analysis_for(path)
    if isinstance(analysis, dict):
        return analysis
    return query.module(analysis, name, limit=limit)


@server.tool()
def callers(path: str, function: str, limit: int = query.DEFAULT_LIMIT) -> dict:
    """List the functions that call `function` in the call graph.

    `function` is a full qualname (e.g. "app.runner.run") or a dotted suffix
    that is unique in the repo (e.g. "runner.run"). An ambiguous suffix
    returns the matching qualnames; an unknown one returns close-match
    suggestions. Each caller is marked `certain` (statically resolved) or
    not (best-effort guess). The `callers` list is capped at `limit`
    (default 50); when cut, `truncated` is true and `total` gives the full count.
    """
    analysis = _analysis_for(path)
    if isinstance(analysis, dict):
        return analysis
    return query.callers(analysis, function, limit=limit)


@server.tool()
def callees(path: str, function: str, limit: int = query.DEFAULT_LIMIT) -> dict:
    """List the functions that `function` calls in the call graph.

    `function` is a full qualname (e.g. "app.main.main") or a dotted suffix
    that is unique in the repo. An ambiguous suffix returns the matching
    qualnames; an unknown one returns close-match suggestions. Each callee is
    marked `certain` (statically resolved) or not (best-effort guess). The
    `callees` list is capped at `limit` (default 50); when cut, `truncated`
    is true and `total` gives the full count.
    """
    analysis = _analysis_for(path)
    if isinstance(analysis, dict):
        return analysis
    return query.callees(analysis, function, limit=limit)


@server.tool()
def trace(path: str, kind: str, limit: int = query.DEFAULT_LIMIT) -> dict:
    """Trace how a source of interest (e.g. "env", "database", "network") flows
    through the call graph to risky sinks.

    Returns the modules the trace reaches and the findings (sink, call site,
    call path). An unknown `kind` returns the valid kinds for this repo. The
    `modules` and `findings` lists are each capped at `limit` (default 50)
    independently; when either is cut, `<field>_truncated` is true and
    `<field>_total` gives the full count.
    """
    analysis = _analysis_for(path)
    if isinstance(analysis, dict):
        return analysis
    return query.trace(analysis, kind, limit=limit)


@server.tool()
def path_between(path: str, source: str, target: str) -> dict:
    """Find a call path from `source` to `target` in the call graph.

    `source` and `target` are full qualnames or unique dotted suffixes.
    Prefers a path made only of statically-certain calls; falls back to one
    that includes guessed calls, marking `certain: false`. Returns
    `{"path": null}` when no path exists.
    """
    analysis = _analysis_for(path)
    if isinstance(analysis, dict):
        return analysis
    return query.path_between(analysis, source, target)


@server.tool()
def search(path: str, text: str, limit: int = query.DEFAULT_LIMIT) -> dict:
    """Search module and function names for a case-insensitive substring.

    Use this to find a starting point when you don't know exact names.
    The `modules` and `functions` lists are each capped at `limit` (default
    50) independently; when either is cut, `<field>_truncated` is true and
    `<field>_total` gives the full count.
    """
    analysis = _analysis_for(path)
    if isinstance(analysis, dict):
        return analysis
    return query.search(analysis, text, limit=limit)


def main() -> None:
    load_dotenv()
    logger.remove()
    logger.add(sys.stderr, level=os.getenv("ARCHSCAN_LOG", "WARNING"), format="<level>{level: <7}</level> {message}")
    server.run()

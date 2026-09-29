import difflib

import networkx as nx

from archscan.export import module_entry, to_json, trace_entry
from archscan.pipeline import Analysis

DEFAULT_LIMIT = 50
CLOSE_MATCHES = 5


def _cap(items: list, limit: int) -> tuple[list, bool, int]:
    limit = max(limit, 0)
    total = len(items)
    return items[:limit], total > limit, total


def _paginate(result: dict, key: str, limit: int) -> dict:
    """Cap `result[key]` at `limit`; add `truncated`/`total` next to it when cut."""
    capped, cut, total = _cap(result[key], limit)
    result[key] = capped
    if cut:
        result["truncated"] = True
        result["total"] = total
    return result


def _paginate_field(result: dict, key: str, limit: int) -> dict:
    """Like `_paginate`, for dicts with more than one capped list.

    Uses `<key>_truncated`/`<key>_total` so two capped lists in the same
    dict (trace's modules/findings, search's modules/functions) don't
    collide on a shared `truncated`/`total` pair.
    """
    capped, cut, total = _cap(result[key], limit)
    result[key] = capped
    if cut:
        result[f"{key}_truncated"] = True
        result[f"{key}_total"] = total
    return result


def _suggest(name: str, names: list[str]) -> list[str]:
    """Close matches on full names, then names whose last dotted segment is a
    close match or contains `name`."""
    matches = difflib.get_close_matches(name, names, n=CLOSE_MATCHES)
    if matches:
        return matches
    found = []
    for n in names:
        last = n.rpartition(".")[2]
        if name in last or difflib.get_close_matches(name, [last], n=1):
            found.append(n)
            if len(found) == CLOSE_MATCHES:
                break
    return found


def _resolve(names: list[str], name: str, limit: int, *, kind: str) -> str | dict:
    """Resolve a full name or a unique dotted suffix to a full name."""
    if name in names:
        return name
    matches = sorted(n for n in names if n.endswith(f".{name}"))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return _paginate({"error": "ambiguous", "matches": matches}, "matches", limit)
    suggestions = _suggest(name, names)
    return {"error": f"unknown {kind}", "suggestions": suggestions}


def _resolve_function(nodes: list[str], name: str, limit: int = DEFAULT_LIMIT) -> str | dict:
    return _resolve(nodes, name, limit, kind="function")


def overview(a: Analysis, limit: int = DEFAULT_LIMIT) -> dict:
    summary = to_json(a)["summary"]
    summary = _paginate_field(summary, "entry_points", limit)
    summary = _paginate_field(summary, "third_party", limit)
    packages: dict[str, dict] = {}
    for module in sorted(a.project.modules(), key=lambda m: m.name):
        top = module.name.split(".", 1)[0]
        package = packages.setdefault(top, {"name": top, "modules": 0, "roles": {}})
        package["modules"] += 1
        judgment = a.judgments.get(module.name)
        if judgment:
            package["roles"][judgment.role] = package["roles"].get(judgment.role, 0) + 1
    result = {"summary": summary, "packages": [packages[name] for name in sorted(packages)]}
    return _paginate(result, "packages", limit)


def module(a: Analysis, name: str, limit: int = DEFAULT_LIMIT) -> dict:
    project = a.project
    names = sorted(m.name for m in project.modules())
    resolved = _resolve(names, name, limit, kind="module")
    if isinstance(resolved, dict):
        return resolved
    entry = module_entry(project, a.judgments, a.capabilities, resolved)
    functions = sorted(
        (fn for fn in project.functions() if fn.module == resolved), key=lambda f: f.qualname
    )
    entry["functions"] = [
        {
            "name": fn.qualname.removeprefix(f"{resolved}."),
            "line": fn.line,
            "calls": project.calls.out_degree(fn.qualname) if project.calls.has_node(fn.qualname) else 0,
        }
        for fn in functions
    ]
    return _paginate(entry, "functions", limit)


def _call_edges(a: Analysis, function: str, limit: int, *, direction: str) -> dict:
    calls = a.project.calls
    resolved = _resolve_function(list(calls.nodes), function, limit)
    if isinstance(resolved, dict):
        return resolved
    edges = calls.in_edges(resolved, data=True) if direction == "in" else calls.out_edges(resolved, data=True)
    other = (lambda u, v: u) if direction == "in" else (lambda u, v: v)
    items = sorted(
        (
            {"function": other(u, v), "certain": not data.get("guess", False)}
            for u, v, data in edges
        ),
        key=lambda e: e["function"],
    )
    key = "callers" if direction == "in" else "callees"
    result = {"function": resolved, key: items}
    return _paginate(result, key, limit)


def callers(a: Analysis, function: str, limit: int = DEFAULT_LIMIT) -> dict:
    return _call_edges(a, function, limit, direction="in")


def callees(a: Analysis, function: str, limit: int = DEFAULT_LIMIT) -> dict:
    return _call_edges(a, function, limit, direction="out")


def trace(a: Analysis, kind: str, limit: int = DEFAULT_LIMIT) -> dict:
    if kind not in a.result.traces:
        return {"error": "unknown kind", "kinds": sorted(a.result.traces)}
    entry = trace_entry(a.project, a.result.traces[kind])
    entry = _paginate_field(entry, "modules", limit)
    entry = _paginate_field(entry, "findings", limit)
    return entry


def path_between(a: Analysis, source: str, target: str) -> dict:
    calls = a.project.calls
    nodes = list(calls.nodes)
    src = _resolve_function(nodes, source)
    if isinstance(src, dict):
        return {**src, "argument": "source"}
    dst = _resolve_function(nodes, target)
    if isinstance(dst, dict):
        return {**dst, "argument": "target"}

    certain_edges = [(u, v) for u, v, data in calls.edges(data=True) if not data.get("guess", False)]
    for graph, certain in ((calls.edge_subgraph(certain_edges), True), (calls, False)):
        try:
            return {"path": nx.shortest_path(graph, src, dst), "certain": certain}
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue
    return {"path": None}


def search(a: Analysis, text: str, limit: int = DEFAULT_LIMIT) -> dict:
    needle = text.lower()
    modules = sorted(m.name for m in a.project.modules() if needle in m.name.lower())
    functions = sorted(fn.qualname for fn in a.project.functions() if needle in fn.qualname.lower())
    result = {"modules": modules, "functions": functions}
    result = _paginate_field(result, "modules", limit)
    result = _paginate_field(result, "functions", limit)
    return result

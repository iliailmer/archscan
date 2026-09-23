import sys
from collections import defaultdict
from html import escape

from archscan.coverage import Coverage, coverage_md, coverage_tab
from archscan.graph import ProjectGraph
from archscan.judge import Judgment
from archscan.trace import TraceResult
from archscan.trace_report import (
    active_traces,
    color_for,
    findings_md,
    functions_html,
    node_id as _node_id,
    LIMITS,
    page_html,
    source_mermaid,
    trace_tabs,
)


def _package(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else name


def _group(project: ProjectGraph, judgments: dict[str, Judgment]) -> dict[str, list[str]]:
    by_role: dict[str, list[str]] = defaultdict(list)
    for module in project.modules():
        role = judgments[module.name].role if module.name in judgments else _package(module.name)
        by_role[role].append(module.name)
    return by_role


def _mermaid(project: ProjectGraph, by_role: dict[str, list[str]]) -> str:
    lines = ["flowchart LR"]
    for role, names in sorted(by_role.items()):
        connected = [n for n in sorted(names) if project.graph.degree(n)]
        if not connected:
            continue
        lines.append(f'  subgraph g{_node_id(role)}["{role}"]')
        for name in connected:
            lines.append(f'    {_node_id(name)}["{name}"]')
        lines.append("  end")
    for source, target in sorted(project.graph.edges):
        lines.append(f"  {_node_id(source)} --> {_node_id(target)}")
    return "\n".join(lines)


def _unconnected(project: ProjectGraph) -> list[str]:
    return sorted(n for n in project.graph.nodes if not project.graph.degree(n))


def _dependencies(project: ProjectGraph) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return (third-party, stdlib) packages, each mapped to the modules that import it."""
    local = {name.split(".")[0] for name in project.graph.nodes}
    third_party: dict[str, list[str]] = defaultdict(list)
    stdlib: dict[str, list[str]] = defaultdict(list)
    for module in project.modules():
        for package in {imp.split(".")[0] for imp in module.external_imports}:
            if package in local:
                continue
            target = stdlib if package in sys.stdlib_module_names else third_party
            target[package].append(module.name)
    return third_party, stdlib


def _details(project: ProjectGraph, judgments: dict[str, Judgment], name: str) -> str:
    module = project.module(name)
    parts = []
    if name in judgments:
        caps = judgments[name].active_capabilities
        if caps:
            parts.append("capabilities: " + ", ".join(caps))
    if module.entry_points:
        parts.append("entry: " + ", ".join(module.entry_points))
    if module.risks:
        parts.append("risks: " + ", ".join(module.risks))
    return "; ".join(parts)


def render(
    project: ProjectGraph,
    judgments: dict[str, Judgment],
    result: TraceResult | None = None,
    coverage: Coverage | None = None,
) -> str:
    by_role = _group(project, judgments)
    lines = [
        f"# archscan: {project.root.name}",
        "",
        "## Flow",
        "",
        "```mermaid",
        _mermaid(project, by_role),
        "```",
        "",
        "## Modules",
        "",
    ]
    for role, names in sorted(by_role.items()):
        lines += [f"### {role}", ""]
        for name in sorted(names):
            details = _details(project, judgments, name)
            suffix = f" — {details}" if details else ""
            lines.append(f"- `{name}` ({project.module(name).path}){suffix}")
        lines.append("")
    lines += ["## Not connected", "", "No internal imports in either direction.", ""]
    for name in _unconnected(project):
        details = _details(project, judgments, name)
        lines.append(f"- `{name}` ({project.module(name).path})" + (f" — {details}" if details else ""))
    lines.append("")
    third_party, stdlib = _dependencies(project)
    lines += ["## Dependencies", "", "### Third-party", ""]
    for package, users in sorted(third_party.items(), key=lambda item: (-len(item[1]), item[0])):
        lines.append(f"- `{package}` — {len(users)} modules")
    lines += ["", "### Standard library", "", ", ".join(f"`{p}`" for p in sorted(stdlib)), ""]
    traces = active_traces(result)
    if traces:
        lines += ["## Data trace", "", LIMITS, ""]
        for trace in traces:
            diagram = source_mermaid(project, trace, color_for(trace.kind))
            lines += [
                f"### {trace.kind}",
                "",
                *(["```mermaid", diagram, "```"] if diagram else ["No modules reached by this source."]),
                "",
                *findings_md(trace),
                "",
            ]
    if coverage is not None:
        lines += coverage_md(coverage)
    return "\n".join(lines)


def render_html(
    project: ProjectGraph,
    judgments: dict[str, Judgment],
    result: TraceResult | None = None,
    coverage: Coverage | None = None,
) -> str:
    by_role = _group(project, judgments)
    sections = []
    for role, names in sorted(by_role.items()):
        items = []
        for name in sorted(names):
            details = _details(project, judgments, name)
            suffix = f" — {escape(details)}" if details else ""
            path = escape(str(project.module(name).path))
            items.append(
                f"<li><code>{escape(name)}</code> ({path}){suffix}{functions_html(project, name)}</li>"
            )
        sections.append(f"<h3>{escape(role)}</h3><ul>{''.join(items)}</ul>")
    unconnected = "".join(
        f"<li><code>{escape(name)}</code> ({escape(str(project.module(name).path))})"
        + (f" — {escape(_details(project, judgments, name))}" if _details(project, judgments, name) else "")
        + "</li>"
        for name in _unconnected(project)
    )
    third_party, stdlib = _dependencies(project)
    rows ="".join(
        f"<tr><td><code>{escape(package)}</code></td><td>{len(users)}</td>"
        f"<td>{escape(', '.join(sorted(users)))}</td></tr>"
        for package, users in sorted(third_party.items(), key=lambda item: (-len(item[1]), item[0]))
    )
    stdlib_list = ", ".join(f"<code>{escape(p)}</code>" for p in sorted(stdlib))
    dependencies = (
        "<h2>Not connected</h2><p>No internal imports in either direction.</p>"
        f"<ul>{unconnected}</ul>"
        "<h2>Dependencies</h2><h3>Third-party</h3>"
        f"<table><tr><th>Package</th><th>Modules</th><th>Used by</th></tr>{rows}</table>"
        f"<h3>Standard library</h3><p>{stdlib_list}</p>"
    )
    structure = f"""<h2>Flow</h2>
<div class="diagram"><pre class="mermaid">
{escape(_mermaid(project, by_role))}
</pre></div>
<h2>Modules</h2>
{''.join(sections)}
{dependencies}
<p>{escape(LIMITS)}</p>"""
    tabs = trace_tabs(project, result)
    tab = coverage_tab(coverage)
    if tab:
        tabs.append(tab)
    return page_html(escape(project.root.name), structure, tabs)

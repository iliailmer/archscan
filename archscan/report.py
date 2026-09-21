import sys
from collections import defaultdict
from html import escape

from archscan.graph import ProjectGraph
from archscan.judge import Judgment

MERMAID_ESM_URL = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs"


def _package(name: str) -> str:
    return name.rsplit(".", 1)[0] if "." in name else name


def _node_id(name: str) -> str:
    return "n_" + "".join(c if c.isalnum() else "_" for c in name)


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


def render(project: ProjectGraph, judgments: dict[str, Judgment]) -> str:
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
    return "\n".join(lines)


def render_html(project: ProjectGraph, judgments: dict[str, Judgment]) -> str:
    by_role = _group(project, judgments)
    sections = []
    for role, names in sorted(by_role.items()):
        items = []
        for name in sorted(names):
            details = _details(project, judgments, name)
            suffix = f" — {escape(details)}" if details else ""
            path = escape(str(project.module(name).path))
            items.append(f"<li><code>{escape(name)}</code> ({path}){suffix}</li>")
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
    title = escape(project.root.name)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>archscan: {title}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 70rem; padding: 0 1rem; }}
  .diagram {{ overflow: auto; border: 1px solid #ccc; border-radius: 6px; padding: 1rem; }}
  code {{ background: #f2f2f2; padding: 0 .25rem; border-radius: 3px; }}
  table {{ border-collapse: collapse; }}
  th, td {{ border: 1px solid #ccc; padding: .25rem .5rem; text-align: left; vertical-align: top; }}
</style>
</head>
<body>
<h1>archscan: {title}</h1>
<h2>Flow</h2>
<div class="diagram"><pre class="mermaid">
{escape(_mermaid(project, by_role))}
</pre></div>
<h2>Modules</h2>
{''.join(sections)}
{dependencies}
<script type="module">
  import mermaid from "{MERMAID_ESM_URL}";
  mermaid.initialize({{ startOnLoad: true, securityLevel: "strict" }});
</script>
</body>
</html>
"""

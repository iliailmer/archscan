import re
from html import escape

from archscan.graph import ProjectGraph
from archscan.trace import Finding, SourceTrace, TraceResult

MERMAID_ESM_URL = "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs"
KIND_COLORS = {
    "cli": "#1f77b4",
    "env": "#2ca02c",
    "file": "#ff7f0e",
    "network": "#d62728",
    "database": "#9467bd",
}
FALLBACK_COLORS = ["#8c564b", "#e377c2", "#17becf", "#bcbd22"]
LIMITS = (
    "Limits: the trace does not follow data through eval-ed code, dynamic imports, "
    "or decorators that change arguments. Nested functions are analyzed on their own, "
    "and calls into them are not resolved. A finding does not mean the code is unsafe."
)

STYLE = """
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 70rem; padding: 0 1rem; }
  .diagram { overflow: auto; border: 1px solid #ccc; border-radius: 6px; padding: 1rem; }
  code { background: #f2f2f2; padding: 0 .25rem; border-radius: 3px; }
  table { border-collapse: collapse; }
  th, td { border: 1px solid #ccc; padding: .25rem .5rem; text-align: left; vertical-align: top; }
  nav { display: flex; gap: .5rem; margin: 1rem 0; flex-wrap: wrap; }
  nav button { padding: .4rem .8rem; border: 1px solid #ccc; border-radius: 6px; background: #fff; cursor: pointer; }
  nav button.active { background: #222; color: #fff; }
  .guess { color: #888; }
"""

SCRIPT = """
import mermaid from "%s";
mermaid.initialize({ startOnLoad: false, securityLevel: "strict", maxTextSize: 2000000, maxEdges: 20000 });
const rendered = new Set();
async function show(id) {
  document.querySelectorAll(".tab").forEach(t => { t.hidden = t.id !== id; });
  document.querySelectorAll("nav button").forEach(b => b.classList.toggle("active", b.dataset.tab === id));
  if (!rendered.has(id)) {
    rendered.add(id);
    await mermaid.run({ nodes: document.querySelectorAll(`#${id} .mermaid:not([data-lazy])`) });
  }
}
document.querySelectorAll("button.toggle").forEach(button => button.addEventListener("click", async () => {
  const tab = button.closest(".tab");
  const full = tab.querySelector(".diagram.full");
  const showFull = full.hidden;
  full.hidden = !showFull;
  tab.querySelector(".diagram.reduced").hidden = showFull;
  button.textContent = showFull ? button.dataset.showReached : button.dataset.showAll;
  const lazy = full.querySelector(".mermaid[data-lazy]");
  if (showFull && lazy.dataset.lazy !== "done") {
    lazy.dataset.lazy = "done";
    await mermaid.run({ nodes: [lazy] });
  }
}));
document.querySelectorAll("nav button").forEach(b => b.addEventListener("click", () => show(b.dataset.tab)));
show("structure");
""" % MERMAID_ESM_URL


def node_id(name: str) -> str:
    return "n_" + "".join(c if c.isalnum() else "_" for c in name)


def color_for(kind: str) -> str:
    return KIND_COLORS.get(kind) or FALLBACK_COLORS[sum(map(ord, kind)) % len(FALLBACK_COLORS)]


def active_traces(result: TraceResult | None) -> list[SourceTrace]:
    if result is None:
        return []
    return [t for t in result.traces.values() if t.functions or t.findings]


def _module_state(project: ProjectGraph, trace: SourceTrace):
    reached: dict[str, bool] = {}
    for qualname, certain in trace.functions.items():
        module = project.function(qualname).module
        reached[module] = reached.get(module, False) or certain
    sinks = {project.function(f.function).module for f in trace.findings}
    edges: dict[tuple[str, str], bool] = {}
    for (caller, callee), certain in trace.edges.items():
        key = (project.function(caller).module, project.function(callee).module)
        edges[key] = edges.get(key, False) or certain
    return reached, sinks, edges


def shown_modules(project: ProjectGraph, trace: SourceTrace) -> list[str]:
    reached, sinks, _ = _module_state(project, trace)
    return sorted(m.name for m in project.modules() if m.name in reached or m.name in sinks)


def source_mermaid(project: ProjectGraph, trace: SourceTrace, color: str, only_reached: bool = True) -> str:
    """Return the Mermaid diagram of a trace, or an empty string when only_reached finds nothing to draw."""
    reached, sinks, reached_edges = _module_state(project, trace)
    if only_reached:
        connected = shown_modules(project, trace)
        if not connected:
            return ""
        keep = set(connected)
        edge_order = sorted(e for e in project.graph.edges if e[0] in keep and e[1] in keep)
    else:
        connected = sorted(
            m.name for m in project.modules() if project.graph.degree(m.name) or m.name in reached or m.name in sinks
        )
        edge_order = sorted(project.graph.edges)
    lines = ["flowchart LR"]
    lines += [f'  {node_id(name)}["{name}"]' for name in connected]
    lines += [f"  {node_id(s)} --> {node_id(t)}" for s, t in edge_order]
    lines.append("  linkStyle default stroke:#ccc")
    lines.append("  classDef dark fill:#eee,stroke:#bbb,color:#888")
    lines.append(f"  classDef hot fill:{color},stroke:#333,color:#fff")
    lines.append(f"  classDef warm fill:{color}66,stroke:{color},stroke-dasharray:4 3")
    lines.append("  classDef sink stroke:#000,stroke-width:4px")
    for name in connected:
        state = "dark" if name not in reached else ("hot" if reached[name] else "warm")
        lines.append(f"  class {node_id(name)} {state}")
        if name in sinks:
            lines.append(f"  class {node_id(name)} sink")
    for position, edge in enumerate(edge_order):
        if edge in reached_edges:
            dash = "" if reached_edges[edge] else ",stroke-dasharray:5 4"
            lines.append(f"  linkStyle {position} stroke:{color},stroke-width:3px{dash}")
    return "\n".join(lines)


def _confidence(finding: Finding) -> str:
    return "certain" if finding.certain else "guess"


def findings_html(trace: SourceTrace) -> str:
    if not trace.findings:
        return "<p>No findings.</p>"
    rows = "".join(
        f"<tr class=\"{'' if f.certain else 'guess'}\">"
        f"<td>{escape(f.source)} → {escape(f.sink)} (<code>{escape(f.sink_call)}</code>)</td>"
        f"<td><code>{escape(f.function)}</code> line {f.line}</td>"
        f"<td>{escape(' → '.join(f.path))}</td>"
        f"<td>{_confidence(f)}</td></tr>"
        for f in trace.findings
    )
    return f"<table><tr><th>Flow</th><th>Where</th><th>Path</th><th>Confidence</th></tr>{rows}</table>"


def findings_md(trace: SourceTrace) -> list[str]:
    if not trace.findings:
        return ["No findings."]
    return [
        f"- {f.source} → {f.sink} (`{f.sink_call}`) in `{f.function}` line {f.line}: "
        f"{' → '.join(f.path)} ({_confidence(f)})"
        for f in trace.findings
    ]


def functions_html(project: ProjectGraph, module_name: str) -> str:
    names = sorted(fn.qualname.removeprefix(f"{module_name}.") for fn in project.functions() if fn.module == module_name)
    if not names:
        return ""
    items = "".join(f"<li><code>{escape(n)}</code></li>" for n in names)
    return f"<details><summary>{len(names)} functions</summary><ul>{items}</ul></details>"


def trace_tabs(project: ProjectGraph, result: TraceResult | None) -> list[tuple[str, str, str]]:
    tabs = []
    for trace in active_traces(result):
        tab_id = "trace-" + re.sub(r"\W", "-", trace.kind)
        color = color_for(trace.kind)
        reduced = source_mermaid(project, trace, color)
        if reduced:
            total = project.graph.number_of_nodes()
            shown = len(shown_modules(project, trace))
            diagrams = (
                f"<p>Showing {shown} of {total} modules.</p>"
                '<button class="toggle" type="button" data-show-all="Show all modules" '
                'data-show-reached="Show only reached modules">Show all modules</button>'
                f'<div class="diagram reduced"><pre class="mermaid">\n{escape(reduced)}\n</pre></div>'
                '<div class="diagram full" hidden>'
                f'<pre class="mermaid" data-lazy>\n{escape(source_mermaid(project, trace, color, only_reached=False))}\n</pre></div>'
            )
        else:
            diagrams = "<p>No modules reached by this source.</p>"
        body = (
            f"<p>Colored modules receive data from <b>{escape(trace.kind)}</b> sources. "
            "Dashed lines and light colors are guessed. A thick border marks a sink.</p>"
            f"{diagrams}"
            f"<h2>Findings</h2>{findings_html(trace)}<p>{escape(LIMITS)}</p>"
        )
        tabs.append((tab_id, trace.kind, body))
    return tabs


def page_html(title: str, structure: str, tabs: list[tuple[str, str, str]]) -> str:
    buttons = '<button data-tab="structure" class="active">Structure</button>' + "".join(
        f'<button data-tab="{tab_id}">{escape(label)}</button>' for tab_id, label, _ in tabs
    )
    panels = f'<section class="tab" id="structure">{structure}</section>' + "".join(
        f'<section class="tab" id="{tab_id}" hidden>{body}</section>' for tab_id, _, body in tabs
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>archscan: {title}</title>
<style>{STYLE}</style>
</head>
<body>
<h1>archscan: {title}</h1>
<nav>{buttons}</nav>
{panels}
<script type="module">{SCRIPT}</script>
</body>
</html>
"""

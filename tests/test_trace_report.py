from html import escape

from archscan.callgraph import build_call_graph
from archscan.catalog import load_catalog
from archscan.report import render, render_html
from archscan.trace import trace
from archscan.trace_report import LIMITS, source_mermaid


def traced(build, flow_files):
    project = build(flow_files)
    build_call_graph(project)
    return project, trace(project, load_catalog())


def test_html_has_a_tab_per_active_source(build, flow_files):
    project, result = traced(build, flow_files)
    html = render_html(project, {}, result)
    assert 'data-tab="trace-env"' in html
    assert 'data-tab="trace-cli"' not in html
    assert "subprocess.run" in html
    assert "classDef hot" in html
    assert "app.runner.run" in html


def test_html_without_a_trace_has_only_the_structure_tab(build, flow_files):
    project = build(flow_files)
    html = render_html(project, {})
    assert 'data-tab="structure"' in html
    assert 'data-tab="trace-' not in html


def test_markdown_lists_findings(build, flow_files):
    project, result = traced(build, flow_files)
    text = render(project, {}, result)
    assert "## Data trace" in text
    assert "### env" in text
    assert "subprocess.run" in text


def test_module_lists_its_functions(build, flow_files):
    project, result = traced(build, flow_files)
    html = render_html(project, {}, result)
    assert "<details>" in html
    assert "main" in html


def test_markdown_states_the_limits(build, flow_files):
    project, result = traced(build, flow_files)
    assert LIMITS in render(project, {}, result)


def test_html_structure_tab_states_the_limits(build, flow_files):
    project = build(flow_files)
    html = render_html(project, {})
    assert escape(LIMITS) in html.split('id="structure"')[1]


def test_unconnected_reached_module_is_drawn(build):
    project = build({
        "solo.py": "import os\nimport subprocess\n\ndef f():\n    subprocess.run(os.getenv('X'))\n",
    })
    build_call_graph(project)
    env = trace(project, load_catalog()).traces["env"]
    assert '["solo"]' in source_mermaid(project, env, "#2ca02c")


def test_html_raises_the_mermaid_size_limits(build, flow_files):
    html = render_html(build(flow_files), {})
    assert "maxTextSize: 2000000" in html
    assert "maxEdges: 20000" in html


def _edge_lines(mermaid):
    return [l.strip() for l in mermaid.splitlines() if " --> " in l]


def _partial(build):
    project = build({
        "app/__init__.py": "",
        "app/main.py": "import os\nfrom app.runner import run\n\ndef main():\n    run(os.getenv('CMD'))\n",
        "app/runner.py": "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
        "app/a.py": "from app import b\n",
        "app/b.py": "X = 1\n",
    })
    build_call_graph(project)
    return project, trace(project, load_catalog())


def test_reduced_diagram_draws_only_reached_modules(build):
    project, result = _partial(build)
    env = result.traces["env"]
    reduced = source_mermaid(project, env, "#2ca02c")
    full = source_mermaid(project, env, "#2ca02c", only_reached=False)
    assert '["app.main"]' in reduced and '["app.runner"]' in reduced
    assert '["app.a"]' not in reduced and '["app.b"]' not in reduced
    assert _edge_lines(reduced) == ["n_app_main --> n_app_runner"]
    assert '["app.a"]' in full and '["app.b"]' in full
    assert len(_edge_lines(full)) == 2


def test_link_style_indexes_match_emitted_edges(build):
    project, result = _partial(build)
    env = result.traces["env"]
    for only_reached in (True, False):
        text = source_mermaid(project, env, "#2ca02c", only_reached=only_reached)
        edges = _edge_lines(text)
        styled = [int(l.split()[1]) for l in text.splitlines() if l.strip().startswith("linkStyle") and l.split()[1].isdigit()]
        assert styled and all(i < len(edges) for i in styled)
        assert {edges[i] for i in styled} == {"n_app_main --> n_app_runner"}


def test_nothing_reached_gives_no_diagram_and_a_message(build):
    project, result = _partial(build)
    empty = result.traces["cli"]
    assert source_mermaid(project, empty, "#1f77b4") == ""


def test_html_tab_has_toggle_count_and_lazy_full_diagram(build):
    project, result = _partial(build)
    html = render_html(project, {}, result)
    tab = html.split('id="trace-env"')[1]
    assert "Show all modules" in tab
    assert "Showing 2 of 5 modules." in tab
    assert "<pre class=\"mermaid\" data-lazy>" in tab
    assert tab.count("flowchart LR") == 2
    assert ".mermaid:not([data-lazy])" in html
    assert "Show only reached modules" in html
    assert "mermaid.run({ nodes: [lazy] })" in html


def test_markdown_has_only_the_reduced_diagram(build):
    project, result = _partial(build)
    text = render(project, {}, result)
    section = text.split("### env")[1]
    assert section.count("flowchart LR") == 1
    assert '["app.a"]' not in section

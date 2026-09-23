from archscan.coverage import Coverage
from archscan.graph import Function, ProjectGraph
from archscan.judge import Judgment
from archscan.pipeline import Analysis
from archscan.report import _dependencies
from archscan.trace import SourceTrace
from archscan.trace_report import active_traces

SCHEMA_VERSION = 1


def module_entry(project: ProjectGraph, judgments: dict[str, Judgment], name: str) -> dict:
    module = project.module(name)
    judgment = judgments.get(name)
    names = sorted(
        fn.qualname.removeprefix(f"{name}.") for fn in project.functions() if fn.module == name
    )
    return {
        "name": name,
        "path": str(module.path),
        "role": judgment.role if judgment else None,
        "capabilities": sorted(judgment.active_capabilities) if judgment else [],
        "entry_points": module.entry_points,
        "risks": module.risks,
        "imports": sorted(project.graph.successors(name)),
        "imported_by": sorted(project.graph.predecessors(name)),
        "functions": names,
    }


def function_entry(project: ProjectGraph, fn: Function) -> dict:
    calls = [
        {"target": target, "certain": not data.get("guess", False)}
        for target, data in project.calls[fn.qualname].items()
    ]
    calls.sort(key=lambda c: c["target"])
    return {
        "qualname": fn.qualname,
        "module": fn.module,
        "line": fn.line,
        "calls": calls,
    }


def _reached_modules(project: ProjectGraph, trace: SourceTrace) -> list[dict]:
    reached: dict[str, bool] = {}
    for qualname, certain in trace.functions.items():
        module = project.function(qualname).module
        reached[module] = reached.get(module, False) or certain
    return [{"name": name, "certain": reached[name]} for name in sorted(reached)]


def trace_entry(project: ProjectGraph, trace: SourceTrace) -> dict:
    return {
        "kind": trace.kind,
        "modules": _reached_modules(project, trace),
        "findings": [
            {
                "sink": f.sink,
                "sink_call": f.sink_call,
                "function": f.function,
                "line": f.line,
                "path": list(f.path),
                "certain": f.certain,
            }
            for f in trace.findings
        ],
    }


def _summary(analysis: Analysis) -> dict:
    project = analysis.project
    third_party, _ = _dependencies(project)
    entry_points = sorted(
        (module.name, entry) for module in project.modules() for entry in module.entry_points
    )
    traces = active_traces(analysis.result)
    return {
        "modules": project.graph.number_of_nodes(),
        "functions": len(project.functions()),
        "dependencies": project.graph.number_of_edges(),
        "test_modules": analysis.full.graph.number_of_nodes() - project.graph.number_of_nodes(),
        "entry_points": [{"module": module, "entry": entry} for module, entry in entry_points],
        "third_party": [
            {"package": package, "modules": len(users)}
            for package, users in sorted(third_party.items())
        ],
        "findings": {t.kind: len(t.findings) for t in traces if t.findings},
        "converged": analysis.result.converged,
    }


def _coverage_entries(coverage: Coverage | None) -> list[dict] | None:
    if coverage is None:
        return None
    return [
        {"module": m.name, "status": m.status, "covered": m.covered, "total": m.total}
        for m in sorted(coverage.modules, key=lambda m: m.name)
    ]


def to_json(analysis: Analysis) -> dict:
    project = analysis.project
    return {
        "schema": SCHEMA_VERSION,
        "root": analysis.root.name,
        "summary": _summary(analysis),
        "modules": [
            module_entry(project, analysis.judgments, name)
            for name in sorted(m.name for m in project.modules())
        ],
        "functions": [
            function_entry(project, fn)
            for fn in sorted(project.functions(), key=lambda f: f.qualname)
        ],
        "traces": [
            trace_entry(project, t)
            for t in sorted(active_traces(analysis.result), key=lambda t: t.kind)
        ],
        "coverage": _coverage_entries(analysis.coverage),
    }

from collections import Counter
from dataclasses import dataclass
from html import escape

from archscan.graph import ProjectGraph

STATUS_ORDER = ["not covered", "maybe", "imported only", "covered"]


@dataclass
class ModuleCoverage:
    name: str
    status: str
    covered: int
    total: int
    uncovered: list[str]


@dataclass
class Coverage:
    modules: list[ModuleCoverage]

    def counts(self) -> dict[str, int]:
        found = Counter(m.status for m in self.modules)
        return {status: found[status] for status in STATUS_ORDER}

    def sorted_modules(self) -> list[ModuleCoverage]:
        return sorted(self.modules, key=lambda m: (STATUS_ORDER.index(m.status), m.name))

    def summary(self) -> str:
        return ", ".join(f"{count} {status}" for status, count in self.counts().items())


def _reach(project: ProjectGraph) -> dict[str, bool]:
    """Map each reached non-test function to whether some path to it is certain."""
    test_modules = {m.name for m in project.modules() if m.is_test}
    is_test_fn = lambda q: project.function(q).module in test_modules
    reached: dict[str, bool] = {}
    queue: list[tuple[str, bool]] = [(f.qualname, True) for f in project.functions() if f.module in test_modules]
    seen = {(q, c) for q, c in queue}
    while queue:
        current, certain = queue.pop()
        for callee in project.calls.successors(current):
            if is_test_fn(callee):
                continue
            step = certain and not project.calls[current][callee].get("guess", False)
            if (callee, step) in seen:
                continue
            seen.add((callee, step))
            reached[callee] = reached.get(callee, False) or step
            queue.append((callee, step))
    return reached


def compute_coverage(project: ProjectGraph) -> Coverage | None:
    tests = {m.name for m in project.modules() if m.is_test}
    if not tests:
        return None
    reached = _reach(project)
    result = []
    for module in project.modules():
        if module.is_test:
            continue
        fns = [f for f in project.functions() if f.module == module.name and f.name != "<module>"]
        hit = [f for f in fns if f.qualname in reached]
        if any(reached[f.qualname] for f in hit):
            status = "covered"
        elif hit:
            status = "maybe"
        elif any(t in tests for t in project.graph.predecessors(module.name)):
            status = "imported only"
        else:
            status = "not covered"
        if not fns and status == "not covered":
            continue
        missed = sorted(f.qualname for f in fns if f.qualname not in reached)
        result.append(ModuleCoverage(module.name, status, len(hit), len(fns), missed))
    return Coverage(result)


def coverage_tab(coverage: Coverage | None) -> tuple[str, str, str] | None:
    if coverage is None:
        return None
    rows = "".join(
        f"<tr><td><code>{escape(m.name)}</code></td><td>{escape(m.status)}</td>"
        f"<td>{m.covered}/{m.total}</td>"
        f"<td>{escape(', '.join(q.removeprefix(m.name + '.') for q in m.uncovered))}</td></tr>"
        for m in coverage.sorted_modules()
    )
    body = (
        f"<p>{escape(coverage.summary())}</p>"
        "<table><tr><th>Module</th><th>Status</th><th>Covered</th><th>Not reached</th></tr>"
        f"{rows}</table>"
        "<p>Guessed calls count as \"maybe\". The known limits of the trace apply.</p>"
    )
    return "coverage", "Coverage", body


def coverage_md(coverage: Coverage) -> list[str]:
    return [
        "## Test coverage",
        "",
        coverage.summary(),
        "",
        *(f"- `{m.name}` — {m.status} ({m.covered}/{m.total})" for m in coverage.sorted_modules()),
        "",
    ]

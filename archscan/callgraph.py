from archscan.graph import CallOp, Function, ProjectGraph, Target

MAX_CANDIDATES = 3


def qualify(callee: str, bindings: dict[str, str]) -> str:
    head, _, rest = callee.partition(".")
    if head in bindings:
        return bindings[head] + (f".{rest}" if rest else "")
    return callee


def _follow(project: ProjectGraph, full: str) -> str:
    """Follow names re-exported through a package `__init__`."""
    for _ in range(3):
        if project.has_function(full) or project.has_function(f"{full}.__init__"):
            return full
        module, _, name = full.rpartition(".")
        target = project.module(module).bindings.get(name) if project.has_module(module) else None
        if target is None or target == full:
            return full
        full = target
    return full


def _by_name(project: ProjectGraph, name: str) -> list[Target]:
    candidates = project.methods_named(name)
    if 1 <= len(candidates) <= MAX_CANDIDATES:
        return [Target(q, True) for q in candidates]
    return []


def resolve_call(project: ProjectGraph, fn: Function, op: CallOp) -> list[Target]:
    module = project.module(fn.module)
    head, _, rest = op.callee.partition(".")
    if head in ("self", "cls") and fn.class_name and rest:
        qualname = f"{fn.module}.{fn.class_name}.{rest}"
        if project.has_function(qualname):
            return [Target(qualname, False)]
        return _by_name(project, rest.rpartition(".")[2])
    bases = [f"{fn.module}.{op.callee}", _follow(project, qualify(op.callee, module.bindings))]
    for base in bases:
        for candidate in (base, f"{base}.__init__"):
            if project.has_function(candidate):
                return [Target(candidate, False)]
    if op.callee.startswith("?.") or (rest and head not in module.bindings):
        return _by_name(project, op.callee.rpartition(".")[2])
    return []


def build_call_graph(project: ProjectGraph) -> None:
    project.calls.clear()
    project.call_targets.clear()
    for fn in project.functions():
        project.calls.add_node(fn.qualname)
    for fn in project.functions():
        for index, op in enumerate(fn.ops):
            if not isinstance(op, CallOp):
                continue
            targets = resolve_call(project, fn, op)
            if not targets:
                continue
            project.call_targets[(fn.qualname, index)] = targets
            for target in targets:
                old = project.calls.get_edge_data(fn.qualname, target.qualname)
                guess = target.guess and (old["guess"] if old else True)
                project.calls.add_edge(fn.qualname, target.qualname, guess=guess)

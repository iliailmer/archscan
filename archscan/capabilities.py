from archscan.callgraph import qualify
from archscan.catalog import Catalog
from archscan.graph import AssignOp, CallOp, Function, ProjectGraph, ReturnOp


def _read_names(op: AssignOp | ReturnOp | CallOp) -> list[str]:
    if isinstance(op, CallOp):
        names = [n for arg in op.args for n in arg]
        names += [n for _, value in op.kwargs for n in value]
        if op.receiver:
            names.append(op.receiver)
        return names
    return list(op.reads)


def _kinds(fn: Function, catalog: Catalog, bindings: dict[str, str]) -> set[str]:
    kinds: set[str] = set()
    for decorator in fn.decorators:
        for kind in catalog.decorator_kinds(qualify(decorator, bindings)):
            kinds.add("decorator:network" if kind == "network" else kind)
    for op in fn.ops:
        if isinstance(op, CallOp):
            callee = qualify(op.callee, bindings)
            kinds.update(catalog.source_kinds(callee))
            kinds.update(catalog.sink_kinds(callee))
        for name in _read_names(op):
            kinds.update(catalog.source_kinds(qualify(name, bindings)))
    return kinds


def derive_capabilities(project: ProjectGraph, catalog: Catalog, module_name: str) -> list[str]:
    """Return the active capability names for `module_name`, sorted."""
    bindings = project.module(module_name).bindings
    kinds: set[str] = set()
    for fn in project.functions():
        if fn.module == module_name:
            kinds |= _kinds(fn, catalog, bindings)
    active = set()
    if "database" in kinds:
        active.add("touches_db")
    if "network" in kinds:
        active.add("touches_network")
    if "cli" in kinds or "decorator:network" in kinds:
        active.add("reads_user_input")
    if "env" in kinds:
        active.add("reads_secrets")
    return sorted(active)

from dataclasses import dataclass, field

from archscan.callgraph import qualify
from archscan.catalog import Catalog
from archscan.graph import AssignOp, CallOp, Function, Module, ProjectGraph, ReturnOp

MAX_ROUNDS = 1000


@dataclass(frozen=True)
class Taint:
    certain: bool
    trail: tuple[str, ...] = ()


Labels = dict[str, Taint]


def _join(first: tuple[str, ...], second: tuple[str, ...]) -> tuple[str, ...]:
    return first + tuple(x for x in second if x not in first)


def _extend(trail: tuple[str, ...], name: str) -> tuple[str, ...]:
    return trail if name in trail else trail + (name,)


def _merge(target: Labels, extra: Labels, *, guess: bool = False, via: str | None = None) -> bool:
    """Add labels to target. A certain taint replaces a guessed one. Returns True on change."""
    changed = False
    for label, taint in extra.items():
        certain = taint.certain and not guess
        trail = taint.trail
        if via:
            trail = _extend(trail, via)
        old = target.get(label)
        if old is None or (certain and not old.certain):
            target[label] = Taint(certain, trail)
            changed = True
    return changed


@dataclass(frozen=True)
class SinkHit:
    label: str
    sink_kind: str
    sink_call: str
    function: str
    line: int
    taint: Taint


@dataclass
class Summary:
    returns: Labels = field(default_factory=dict)
    sinks: dict[tuple[str, str, str, int, str], SinkHit] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    source: str
    sink: str
    sink_call: str
    function: str
    line: int
    path: tuple[str, ...]
    certain: bool


@dataclass
class SourceTrace:
    kind: str
    functions: dict[str, bool] = field(default_factory=dict)
    edges: dict[tuple[str, str], bool] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class TraceResult:
    traces: dict[str, SourceTrace]
    converged: bool = True


@dataclass
class _State:
    project: ProjectGraph
    catalog: Catalog
    summaries: dict[str, Summary] = field(default_factory=dict)
    class_attrs: dict[tuple[str, str], dict[str, Labels]] = field(default_factory=dict)
    call_args: dict[tuple[str, int], tuple[list[Labels], dict[str, Labels]]] = field(default_factory=dict)
    envs: dict[str, dict[str, Labels]] = field(default_factory=dict)


def _record_hit(summary: Summary, hit: SinkHit) -> bool:
    key = (hit.label, hit.sink_kind, hit.function, hit.line, hit.sink_call)
    old = summary.sinks.get(key)
    if old is None or (hit.taint.certain and not old.taint.certain):
        summary.sinks[key] = hit
        return True
    return False


def _bind(callee: Function, op: CallOp, args: list[Labels], kwargs: dict[str, Labels]) -> dict[int, Labels]:
    """Map callee parameter positions to the labels of the arguments passed to them."""
    method = bool(callee.params) and callee.params[0] in ("self", "cls")
    shift = 1 if method and (op.receiver is not None or callee.name == "__init__") else 0
    bound: dict[int, Labels] = {}
    for index, labels in enumerate(args):
        _merge(bound.setdefault(index + shift, {}), labels)
    for name, labels in kwargs.items():
        if name in callee.params:
            _merge(bound.setdefault(callee.params.index(name), {}), labels)
    return bound


class _FunctionPass:
    def __init__(self, fn: Function, state: _State) -> None:
        self.fn = fn
        self.state = state
        self.module: Module = state.project.module(fn.module)
        self.summary = state.summaries[fn.qualname]
        self.env = state.envs.setdefault(fn.qualname, {})
        self.changed = False
        self._seed_parameters()

    def _seed_parameters(self) -> None:
        origin = (self.fn.qualname,)
        for index, param in enumerate(self.fn.params):
            if _merge(self.env.setdefault(param, {}), {f"@{index}": Taint(True, origin)}):
                self.changed = True
        for decorator in self.fn.decorators:
            for kind in self.state.catalog.decorator_kinds(qualify(decorator, self.module.bindings)):
                for param in self.fn.params:
                    if param not in ("self", "cls"):
                        if _merge(self.env[param], {kind: Taint(True, origin)}):
                            self.changed = True

    def _labels_of(self, name: str) -> Labels:
        out: Labels = {}
        if name in self.env:
            _merge(out, self.env[name])
        else:
            parts = name.split(".")
            for size in range(len(parts) - 1, 0, -1):
                prefix = ".".join(parts[:size])
                if prefix in self.env:
                    _merge(out, self.env[prefix], guess=True)
                    break
        if self.fn.class_name and name.startswith("self."):
            stored = self.state.class_attrs.get((self.fn.module, self.fn.class_name), {}).get(name)
            if stored:
                _merge(out, stored, guess=True)
        for kind in self.state.catalog.source_kinds(qualify(name, self.module.bindings)):
            _merge(out, {kind: Taint(True, (self.fn.qualname,))})
        return out

    def _read_all(self, names: tuple[str, ...], *, guess: bool = False) -> Labels:
        out: Labels = {}
        for name in names:
            _merge(out, self._labels_of(name), guess=guess)
        return out

    def run(self) -> bool:
        for index, op in enumerate(self.fn.ops):
            match op:
                case AssignOp():
                    self._assign(op)
                case ReturnOp():
                    if _merge(self.summary.returns, self._read_all(op.reads, guess=op.guess)):
                        self.changed = True
                case CallOp():
                    self._call(index, op)
        return self.changed

    def _assign(self, op: AssignOp) -> None:
        new = self._read_all(op.reads, guess=op.guess)
        if _merge(self.env.setdefault(op.target, {}), new):
            self.changed = True
        if op.target.startswith("self.") and self.fn.class_name:
            attrs = self.state.class_attrs.setdefault((self.fn.module, self.fn.class_name), {})
            if _merge(attrs.setdefault(op.target, {}), new, guess=True):
                self.changed = True

    def _call(self, index: int, op: CallOp) -> None:
        fn, state = self.fn, self.state
        args = [self._read_all(names, guess=i in op.guess_args) for i, names in enumerate(op.args)]
        kwargs = {
            name: self._read_all(names, guess=name in op.guess_kwargs) for name, names in op.kwargs
        }
        receiver = self._labels_of(op.receiver) if op.receiver else {}
        state.call_args[(fn.qualname, index)] = (args, kwargs)

        every: Labels = {}
        for labels in [*args, *kwargs.values(), receiver]:
            _merge(every, labels)

        qualified = qualify(op.callee, self.module.bindings)
        result: Labels = {}
        for kind in state.catalog.source_kinds(qualified):
            _merge(result, {kind: Taint(True, (fn.qualname,))})
        for kind in state.catalog.sink_kinds(qualified):
            for label, taint in every.items():
                trail = _extend(taint.trail, fn.qualname)
                hit = SinkHit(label, kind, qualified, fn.qualname, op.line, Taint(taint.certain, trail))
                if _record_hit(self.summary, hit):
                    self.changed = True

        targets = state.project.call_targets.get((fn.qualname, index), [])
        if not targets:
            _merge(result, every, guess=True)
        for target in targets:
            callee = state.project.function(target.qualname)
            summary = state.summaries[target.qualname]
            bound = _bind(callee, op, args, kwargs)
            if callee.name == "__init__":
                _merge(result, every, guess=True)
            for label, taint in summary.returns.items():
                if label.startswith("@"):
                    for source, source_taint in bound.get(int(label[1:]), {}).items():
                        mapped = Taint(source_taint.certain and taint.certain, _join(source_taint.trail, taint.trail))
                        _merge(result, {source: mapped}, guess=target.guess, via=fn.qualname)
                else:
                    _merge(result, {label: taint}, guess=target.guess, via=fn.qualname)
            for hit in list(summary.sinks.values()):
                if not hit.label.startswith("@"):
                    continue
                for source, source_taint in bound.get(int(hit.label[1:]), {}).items():
                    certain = source_taint.certain and hit.taint.certain and not target.guess
                    trail = _join(source_taint.trail, hit.taint.trail)
                    mapped = SinkHit(source, hit.sink_kind, hit.sink_call, hit.function, hit.line, Taint(certain, trail))
                    if _record_hit(self.summary, mapped):
                        self.changed = True
        if _merge(self.env.setdefault(op.target, {}), result):
            self.changed = True


def _mark(table: dict, key, certain: bool) -> None:
    table[key] = table.get(key, False) or certain


def _collect(state: _State, kinds: list[str]) -> TraceResult:
    traces = {kind: SourceTrace(kind) for kind in kinds}
    project = state.project

    seen: dict[tuple, SinkHit] = {}
    for summary in state.summaries.values():
        for hit in summary.sinks.values():
            key = (hit.label, hit.sink_kind, hit.function, hit.line, hit.sink_call, hit.taint.trail)
            old = seen.get(key)
            if hit.label in traces and (old is None or (hit.taint.certain and not old.taint.certain)):
                seen[key] = hit
    for hit in seen.values():
        traces[hit.label].findings.append(
            Finding(hit.label, hit.sink_kind, hit.sink_call, hit.function, hit.line, hit.taint.trail, hit.taint.certain)
        )
    for one in traces.values():
        one.findings.sort(key=lambda f: (f.function, f.line, f.sink_call))

    for qualname, env in state.envs.items():
        for labels in env.values():
            for label, taint in labels.items():
                if label in traces:
                    _mark(traces[label].functions, qualname, taint.certain)

    work: list[tuple[str, int, str, bool]] = []
    visited: set[tuple[str, int, str, bool]] = set()

    def push(callee: str, position: int, label: str, certain: bool) -> None:
        if (callee, position, label, certain) not in visited:
            visited.add((callee, position, label, certain))
            work.append((callee, position, label, certain))

    for (caller, index), (args, kwargs) in state.call_args.items():
        op = project.function(caller).ops[index]
        for target in project.call_targets.get((caller, index), []):
            callee = project.function(target.qualname)
            for position, labels in _bind(callee, op, args, kwargs).items():
                for label, taint in labels.items():
                    if label in traces:
                        certain = taint.certain and not target.guess
                        _mark(traces[label].functions, caller, taint.certain)
                        _mark(traces[label].edges, (caller, target.qualname), certain)
                        push(target.qualname, position, label, certain)

    while work:
        qualname, position, label, certain = work.pop()
        _mark(traces[label].functions, qualname, certain)
        fn = project.function(qualname)
        for index, op in enumerate(fn.ops):
            entry = state.call_args.get((qualname, index))
            if not isinstance(op, CallOp) or entry is None:
                continue
            args, kwargs = entry
            for target in project.call_targets.get((qualname, index), []):
                callee = project.function(target.qualname)
                for next_position, labels in _bind(callee, op, args, kwargs).items():
                    marker = labels.get(f"@{position}")
                    if marker is not None:
                        onward = certain and marker.certain and not target.guess
                        _mark(traces[label].edges, (qualname, target.qualname), onward)
                        push(target.qualname, next_position, label, onward)
    return TraceResult(traces)


def trace(project: ProjectGraph, catalog: Catalog, only: str | None = None) -> TraceResult:
    state = _State(project, catalog)
    for fn in project.functions():
        state.summaries[fn.qualname] = Summary()
    converged = False
    for _ in range(MAX_ROUNDS):
        changed = False
        for fn in project.functions():
            if _FunctionPass(fn, state).run():
                changed = True
        if not changed:
            converged = True
            break
    kinds = [k for k in catalog.kinds() if only is None or k == only]
    result = _collect(state, kinds)
    result.converged = converged
    return result

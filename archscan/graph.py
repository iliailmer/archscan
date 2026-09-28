from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx


@dataclass(frozen=True)
class CallOp:
    target: str
    callee: str
    args: tuple[tuple[str, ...], ...]
    kwargs: tuple[tuple[str, tuple[str, ...]], ...]
    receiver: str | None
    line: int
    guess_args: frozenset[int] = frozenset()
    guess_kwargs: frozenset[str] = frozenset()


@dataclass(frozen=True)
class AssignOp:
    target: str
    reads: tuple[str, ...]
    guess: bool = False


@dataclass(frozen=True)
class ReturnOp:
    reads: tuple[str, ...]
    guess: bool = False


Op = CallOp | AssignOp | ReturnOp


@dataclass
class Function:
    qualname: str
    module: str
    name: str
    class_name: str | None
    params: list[str]
    decorators: list[str]
    ops: list[Op]
    line: int


@dataclass(frozen=True)
class Target:
    qualname: str
    guess: bool


@dataclass
class Module:
    name: str
    path: Path
    external_imports: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    bindings: dict[str, str] = field(default_factory=dict)
    is_test: bool = False
    has_code: bool = True


class ProjectGraph:
    def __init__(self, root: Path):
        self.root = root
        self.graph: nx.DiGraph = nx.DiGraph()
        self.calls: nx.DiGraph = nx.DiGraph()
        self.call_targets: dict[tuple[str, int], list[Target]] = {}
        self._functions: dict[str, Function] = {}
        self._methods: dict[str, list[str]] = {}
        self.skipped: dict[str, int] = {}

    def add_module(self, module: Module) -> None:
        self.graph.add_node(module.name, module=module)

    def add_dependency(self, source: str, target: str) -> None:
        self.graph.add_edge(source, target)

    def modules(self) -> list[Module]:
        return [data["module"] for _, data in self.graph.nodes(data=True)]

    def module(self, name: str) -> Module:
        return self.graph.nodes[name]["module"]

    def has_module(self, name: str) -> bool:
        return name in self.graph

    def add_function(self, fn: Function) -> None:
        if fn.qualname in self._functions:
            return
        self._functions[fn.qualname] = fn
        if fn.class_name:
            self._methods.setdefault(fn.name, []).append(fn.qualname)

    def functions(self) -> list[Function]:
        return list(self._functions.values())

    def function(self, qualname: str) -> Function:
        return self._functions[qualname]

    def has_function(self, qualname: str) -> bool:
        return qualname in self._functions

    def methods_named(self, name: str) -> list[str]:
        return self._methods.get(name, [])

    def without_tests(self) -> "ProjectGraph":
        kept = ProjectGraph(self.root)
        for module in self.modules():
            if not module.is_test:
                kept.add_module(module)
        for source, target in self.graph.edges:
            if kept.has_module(source) and kept.has_module(target):
                kept.add_dependency(source, target)
        for fn in self.functions():
            if kept.has_module(fn.module):
                kept.add_function(fn)
        return kept

from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx


@dataclass
class Module:
    name: str
    path: Path
    language: str
    external_imports: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)


class ProjectGraph:
    def __init__(self, root: Path):
        self.root = root
        self.graph: nx.DiGraph = nx.DiGraph()

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

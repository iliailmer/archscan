import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from importlib.resources import files
from pathlib import Path


@dataclass(frozen=True)
class Entry:
    kind: str
    match: tuple[str, ...] = ()
    decorator: tuple[str, ...] = ()


def _matches(patterns: tuple[str, ...], name: str) -> bool:
    return any(fnmatchcase(name, pattern) for pattern in patterns)


@dataclass(frozen=True)
class Catalog:
    sources: tuple[Entry, ...]
    sinks: tuple[Entry, ...]

    def source_kinds(self, name: str) -> list[str]:
        return [e.kind for e in self.sources if _matches(e.match, name)]

    def decorator_kinds(self, name: str) -> list[str]:
        return [e.kind for e in self.sources if _matches(e.decorator, name)]

    def sink_kinds(self, name: str) -> list[str]:
        return [e.kind for e in self.sinks if _matches(e.match, name)]

    def kinds(self) -> list[str]:
        return sorted({e.kind for e in self.sources})


def _parse(text: str) -> tuple[list[Entry], list[Entry]]:
    data = tomllib.loads(text)

    def entries(key: str) -> list[Entry]:
        return [
            Entry(item["kind"], tuple(item.get("match", ())), tuple(item.get("decorator", ())))
            for item in data.get(key, [])
        ]

    return entries("source"), entries("sink")


def load_catalog(project_root: Path | None = None) -> Catalog:
    sources, sinks = _parse((files("archscan") / "catalog.toml").read_text())
    if project_root is not None:
        extra = project_root / "sources.toml"
        if extra.is_file():
            more_sources, more_sinks = _parse(extra.read_text())
            sources += more_sources
            sinks += more_sinks
    return Catalog(tuple(sources), tuple(sinks))

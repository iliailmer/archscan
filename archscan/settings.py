import tomllib
from pathlib import Path

DEFAULT_SKIP_DIRS = frozenset({
    ".venv", "venv", "__pycache__", ".git", "node_modules", ".tox", "build", "dist",
    "doc", "docs", "benchmarks", "examples",
})
LOG_HIDDEN = frozenset({"__pycache__", "node_modules", "build", "dist", "venv"})


def _names(section: dict, key: str) -> set[str]:
    value = section.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"[scan] {key} must be a list of strings")
    return set(value)


def load_scan_settings(root: Path) -> set[str]:
    skip = set(DEFAULT_SKIP_DIRS)
    path = root / "archscan.toml"
    if path.is_file():
        section = tomllib.loads(path.read_text()).get("scan", {})
        if not isinstance(section, dict):
            raise ValueError("scan must be a table")
        skip |= _names(section, "skip")
        skip -= _names(section, "keep")
    return skip

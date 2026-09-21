from pathlib import Path

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from archscan.graph import Module, ProjectGraph

SKIP_DIRS = {".venv", "venv", "__pycache__", ".git", "node_modules", ".tox", "build", "dist"}
RISK_CALLS = {"eval", "exec", "compile", "os.system", "pickle.loads", "yaml.load"}
RISK_PREFIXES = ("subprocess.",)

_parser = Parser(Language(tree_sitter_python.language()))


def scan(root: Path) -> ProjectGraph:
    project = ProjectGraph(root)
    sources: dict[str, bytes] = {}
    is_package: dict[str, bool] = {}
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if SKIP_DIRS & set(rel.parts):
            continue
        name, package = _module_name(rel)
        sources[name] = path.read_bytes()
        is_package[name] = package
        project.add_module(Module(name=name, path=rel, language="python"))

    for name, source in sources.items():
        module = project.module(name)
        tree = _parser.parse(source)
        for imp in _imports(tree.root_node):
            targets = _resolve(imp, name, is_package[name], project)
            if targets:
                for target in targets:
                    if target != name:
                        project.add_dependency(name, target)
            else:
                if imp[0] == 0 and imp[1]:
                    module.external_imports.append(imp[1])
        module.entry_points = _entry_points(tree.root_node)
        module.risks = _risks(tree.root_node)
    return project


def _module_name(rel: Path) -> tuple[str, bool]:
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        return ".".join(parts[:-1]) or "__root__", True
    return ".".join(parts), False


def _text(node: Node) -> str:
    return node.text.decode() if node.text else ""


def _imports(root: Node) -> list[tuple[int, str, list[str]]]:
    """Return (relative level, module, imported names) per import statement."""
    found: list[tuple[int, str, list[str]]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "import_statement":
            for child in node.named_children:
                target = child.child_by_field_name("name") if child.type == "aliased_import" else child
                if target is not None:
                    found.append((0, _text(target), []))
        elif node.type == "import_from_statement":
            module_node = node.child_by_field_name("module_name")
            level, module = 0, ""
            if module_node is not None:
                if module_node.type == "relative_import":
                    text = _text(module_node)
                    level = len(text) - len(text.lstrip("."))
                    module = text.lstrip(".")
                else:
                    module = _text(module_node)
            names = []
            for child in node.children_by_field_name("name"):
                target = child.child_by_field_name("name") if child.type == "aliased_import" else child
                if target is not None:
                    names.append(_text(target))
            if node.child(node.child_count - 1) is not None and _text(node.child(node.child_count - 1)) == "*":
                names = []
            found.append((level, module, names))
        else:
            stack.extend(node.children)
    return found


def _resolve(imp: tuple[int, str, list[str]], current: str, package: bool, project: ProjectGraph) -> list[str]:
    level, module, names = imp
    if level:
        base = current.split(".")
        if not package:
            base = base[:-1]
        base = base[: len(base) - (level - 1)]
        module = ".".join(base + ([module] if module else []))
    found = _match(module, names, project)
    if found or level:
        return found
    directory = current if package else current.rpartition(".")[0]
    if directory:
        return _match(f"{directory}.{module}", names, project)
    return []


def _match(module: str, names: list[str], project: ProjectGraph) -> list[str]:
    candidates = [f"{module}.{n}" if module else n for n in names]
    targets = [c for c in candidates if project.has_module(c)]
    if targets:
        return targets
    if module and project.has_module(module):
        return [module]
    return []


def _entry_points(root: Node) -> list[str]:
    found = []
    for node in root.children:
        if node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            if cond is not None and "__name__" in _text(cond) and "__main__" in _text(cond):
                found.append("__main__")
        if node.type == "decorated_definition":
            for dec in node.children:
                if dec.type == "decorator":
                    text = _text(dec)
                    if any(k in text for k in (".get(", ".post(", ".put(", ".delete(", ".patch(", ".route(")):
                        found.append(text.lstrip("@").strip())
    return found


def _risks(root: Node) -> list[str]:
    found = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "call":
            fn = node.child_by_field_name("function")
            if fn is not None:
                name = _text(fn)
                if name in RISK_CALLS or name.startswith(RISK_PREFIXES):
                    found.append(f"{name} (line {node.start_point[0] + 1})")
        stack.extend(node.children)
    return sorted(found)

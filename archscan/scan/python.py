from pathlib import Path

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from archscan.graph import AssignOp, Function, Module, ProjectGraph
from archscan.scan.python_functions import extract_functions
from archscan.settings import DEFAULT_SKIP_DIRS

RISK_CALLS = {"eval", "exec", "compile", "os.system", "pickle.loads", "yaml.load"}
RISK_PREFIXES = ("subprocess.",)

_parser = Parser(Language(tree_sitter_python.language()))


def scan(root: Path, skip: set[str] | None = None) -> ProjectGraph:
    skip = DEFAULT_SKIP_DIRS if skip is None else skip
    project = ProjectGraph(root)
    sources: dict[str, bytes] = {}
    is_package: dict[str, bool] = {}
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        hit = next((part for part in rel.parts if part in skip), None)
        if hit:
            project.skipped[hit] = project.skipped.get(hit, 0) + 1
            continue
        name, package = _module_name(rel)
        sources[name] = path.read_bytes()
        is_package[name] = package
        project.add_module(Module(name=name, path=rel, language="python", is_test=is_test_path(rel)))

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
        module.bindings = _bindings(tree.root_node, name, is_package[name], project)
        functions = extract_functions(tree.root_node, name)
        for fn in functions:
            project.add_function(fn)
        module.has_code = any(_is_code(fn) for fn in functions) or _has_definition(tree.root_node)
    return project


def is_test_path(rel: Path) -> bool:
    name = rel.name
    return (
        bool({"tests", "test"} & set(rel.parts))
        or (name.startswith("test_") and name.endswith(".py"))
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


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
    module = _absolute(level, module, current, package)
    found = _match(module, names, project)
    if found or level:
        return found
    directory = current if package else current.rpartition(".")[0]
    if directory:
        return _match(f"{directory}.{module}", names, project)
    return []


def _absolute(level: int, module: str, current: str, package: bool) -> str:
    if not level:
        return module
    base = current.split(".")
    if not package:
        base = base[:-1]
    base = base[: len(base) - (level - 1)]
    return ".".join(base + ([module] if module else []))


def _localize(module: str, current: str, package: bool, project: ProjectGraph) -> str:
    """Resolve a script-style import of a sibling module, such as `import _common`."""
    if not module or project.has_module(module):
        return module
    directory = current if package else current.rpartition(".")[0]
    sibling = f"{directory}.{module}" if directory else module
    return sibling if project.has_module(sibling) else module


def _bindings(root: Node, current: str, package: bool, project: ProjectGraph) -> dict[str, str]:
    """Map each name an import binds to the dotted name it refers to."""
    bound: dict[str, str] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type == "aliased_import":
                    name = _text(child.child_by_field_name("name"))
                    bound[_text(child.child_by_field_name("alias"))] = _localize(name, current, package, project)
                else:
                    name = _text(child)
                    if "." in name:
                        bound[name.split(".")[0]] = name.split(".")[0]
                    else:
                        bound[name] = _localize(name, current, package, project)
        elif node.type == "import_from_statement":
            module_node = node.child_by_field_name("module_name")
            level, module = 0, ""
            if module_node is not None:
                text = _text(module_node)
                if module_node.type == "relative_import":
                    level = len(text) - len(text.lstrip("."))
                    module = text.lstrip(".")
                else:
                    module = text
            module = _absolute(level, module, current, package)
            if not level:
                module = _localize(module, current, package, project)
            for child in node.children_by_field_name("name"):
                if child.type == "aliased_import":
                    name = _text(child.child_by_field_name("name"))
                    alias = _text(child.child_by_field_name("alias"))
                else:
                    name = alias = _text(child)
                bound[alias] = f"{module}.{name}" if module else name
        else:
            stack.extend(node.children)
    return bound


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


def _is_code(fn: Function) -> bool:
    if fn.name != "<module>":
        return True
    return any(not (isinstance(op, AssignOp) and op.target == "__all__") for op in fn.ops)


def _has_definition(root: Node) -> bool:
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in ("function_definition", "class_definition"):
            return True
        stack.extend(node.children)
    return False


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

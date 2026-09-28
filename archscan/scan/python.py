import tomllib
from pathlib import Path

import tree_sitter_python
from tree_sitter import Language, Node, Parser

from archscan.callgraph import qualify
from archscan.catalog import Catalog, load_catalog
from archscan.graph import AssignOp, Function, Module, ProjectGraph
from archscan.scan.python_functions import _text, extract_functions
from archscan.settings import DEFAULT_SKIP_DIRS

_parser = Parser(Language(tree_sitter_python.language()))

Import = tuple[int, str, list[tuple[str, str]]]


def scan(root: Path, skip: set[str] | None = None, catalog: Catalog | None = None) -> ProjectGraph:
    skip = DEFAULT_SKIP_DIRS if skip is None else skip
    catalog = load_catalog() if catalog is None else catalog
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
        project.add_module(Module(name=name, path=rel, is_test=is_test_path(rel)))

    for name, source in sources.items():
        module = project.module(name)
        tree = _parser.parse(source)
        imports = _imports(tree.root_node)
        for imp in imports:
            level, imp_module, entries = imp
            targets = _resolve(imp, name, is_package[name], project)
            if targets:
                for target in targets:
                    if target != name:
                        project.add_dependency(name, target)
            elif level == 0:
                external = imp_module or (entries[0][0] if entries else "")
                if external:
                    module.external_imports.append(external)
        module.entry_points = _entry_points(tree.root_node)
        if module.path.name == "__main__.py" and "__main__" not in module.entry_points:
            module.entry_points.append("__main__")
        module.bindings = _bindings(imports, name, is_package[name], project)
        module.risks = _risks(tree.root_node, module.bindings, catalog)
        functions = extract_functions(tree.root_node, name)
        for fn in functions:
            project.add_function(fn)
        module.has_code = any(_is_code(fn) for fn in functions) or _has_top_class(tree.root_node)
    _apply_pyproject_scripts(root, project)
    return project


def _project_scripts(data: dict) -> list[tuple[str, str, str]]:
    """Return (script name, module, function) from [project.scripts]/[project.gui-scripts].

    Any wrong shape (a non-table `project`, a non-table scripts section, or a
    non-string target) is treated as "no scripts" rather than raised: a
    malformed pyproject.toml must never fail the scan.
    """
    found = []
    for key in ("scripts", "gui-scripts"):
        try:
            items = list(data["project"][key].items())
        except (KeyError, TypeError, AttributeError):
            continue
        for script_name, target in items:
            if not isinstance(target, str):
                continue
            module, _, func = target.partition(":")
            found.append((script_name, module, func))
    return found


def _resolve_script_module(module: str, project: ProjectGraph) -> str | None:
    if project.has_module(module):
        return module
    suffix = f".{module}"
    matches = [m.name for m in project.modules() if m.name.endswith(suffix)]
    return matches[0] if len(matches) == 1 else None


def _apply_pyproject_scripts(root: Path, project: ProjectGraph) -> None:
    path = root / "pyproject.toml"
    if not path.is_file():
        return
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError:
        return
    for script_name, module, func in _project_scripts(data):
        resolved = _resolve_script_module(module, project)
        if resolved is not None:
            project.module(resolved).entry_points.append(f"script {script_name} -> {func}")


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


def _name_alias(child: Node) -> tuple[str, str]:
    """Return (imported name, bound alias) for one `import`/`from` target."""
    if child.type == "aliased_import":
        return _text(child.child_by_field_name("name")), _text(child.child_by_field_name("alias"))
    text = _text(child)
    return text, text


def _imports(root: Node) -> list[Import]:
    """Return (relative level, module, [(imported name, bound alias)]) per import.

    For `import a.b [as c]`, module is "" and the single entry's name is the
    full dotted target ("a.b"); an unaliased entry has name == alias. For
    `from mod import a [as b], ...` (or `from mod import *`, entries empty),
    module is the "from" target.
    """
    found: list[Import] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "import_statement":
            for child in node.named_children:
                found.append((0, "", [_name_alias(child)]))
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
            names = [_name_alias(child) for child in node.children_by_field_name("name")]
            last = node.child(node.child_count - 1)
            if last is not None and _text(last) == "*":
                names = []
            found.append((level, module, names))
        else:
            stack.extend(node.children)
    return found


def _resolve(imp: Import, current: str, package: bool, project: ProjectGraph) -> list[str]:
    level, module, entries = imp
    names = [name for name, _ in entries]
    module = _absolute(level, module, current, package)
    found = _match(module, names, project)
    if found or level:
        return found
    directory = current if package else current.rpartition(".")[0]
    if not directory:
        return []
    if module:
        return _match(f"{directory}.{module}", names, project)
    return [sibling for n in names if (sibling := _sibling(n, current, package, project)) is not None]


def _absolute(level: int, module: str, current: str, package: bool) -> str:
    if not level:
        return module
    base = current.split(".")
    if not package:
        base = base[:-1]
    base = base[: len(base) - (level - 1)]
    return ".".join(base + ([module] if module else []))


def _sibling(name: str, current: str, package: bool, project: ProjectGraph) -> str | None:
    """Resolve a script-style sibling module, such as `import _common`, to its
    dotted package path, or None if no such sibling module exists."""
    directory = current if package else current.rpartition(".")[0]
    if not directory:
        return None
    candidate = f"{directory}.{name}"
    return candidate if project.has_module(candidate) else None


def _localize(module: str, current: str, package: bool, project: ProjectGraph) -> str:
    if not module or project.has_module(module):
        return module
    return _sibling(module, current, package, project) or module


def _bindings(imports: list[Import], current: str, package: bool, project: ProjectGraph) -> dict[str, str]:
    """Map each name an import binds to the dotted name it refers to."""
    bound: dict[str, str] = {}
    for level, module, entries in imports:
        if not module and not level:
            for name, alias in entries:
                if name != alias:
                    bound[alias] = _localize(name, current, package, project)
                elif "." in name:
                    bound[name.split(".")[0]] = name.split(".")[0]
                else:
                    bound[name] = _localize(name, current, package, project)
            continue
        base = _absolute(level, module, current, package)
        if not level:
            base = _localize(base, current, package, project)
        for name, alias in entries:
            bound[alias] = f"{base}.{name}" if base else name
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


def _has_top_class(root: Node) -> bool:
    """A top-level class makes a module non-empty even with no methods
    (`extract_functions` only yields entries for function definitions)."""
    for child in root.named_children:
        definition = child.child_by_field_name("definition") if child.type == "decorated_definition" else child
        if definition is not None and definition.type == "class_definition":
            return True
    return False


def _risks(root: Node, bindings: dict[str, str], catalog: Catalog) -> list[str]:
    """A call is a risk when its qualified name matches a `process` sink."""
    found = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "call":
            fn = node.child_by_field_name("function")
            if fn is not None:
                qualified = qualify(_text(fn), bindings)
                if "process" in catalog.sink_kinds(qualified):
                    found.append(f"{qualified} (line {node.start_point[0] + 1})")
        stack.extend(node.children)
    return sorted(found)

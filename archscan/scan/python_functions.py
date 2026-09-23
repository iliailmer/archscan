from tree_sitter import Node

from archscan.graph import AssignOp, CallOp, Function, Op, ReturnOp

CONTAINER_TYPES = {
    "list",
    "tuple",
    "dictionary",
    "set",
    "expression_list",
    "list_comprehension",
    "set_comprehension",
    "dictionary_comprehension",
    "generator_expression",
    "subscript",
}
MULTI_TARGET_TYPES = {"pattern_list", "tuple_pattern", "list_pattern"}


def _text(node: Node) -> str:
    return node.text.decode() if node.text else ""


def _dotted(node: Node | None) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return _text(node)
    if node.type == "attribute":
        base = _dotted(node.child_by_field_name("object"))
        attr = node.child_by_field_name("attribute")
        if base and attr is not None:
            return f"{base}.{_text(attr)}"
    return None


class _Builder:
    def __init__(self) -> None:
        self.ops: list[Op] = []
        self._temps = 0

    def _temp(self) -> str:
        self._temps += 1
        return f"$t{self._temps}"

    def statement(self, node: Node) -> None:
        match node.type:
            case "function_definition" | "class_definition" | "decorated_definition":
                return
            case "assignment":
                right = node.child_by_field_name("right")
                if right is None:
                    return
                names, guess = self.reads(right)
                self._assign_to(node.child_by_field_name("left"), tuple(names), guess)
            case "augmented_assignment":
                left = node.child_by_field_name("left")
                names, guess = self.reads(node.child_by_field_name("right"))
                self._assign_to(left, tuple(names) + tuple(self._target_names(left)), guess)
            case "return_statement" | "yield":
                for child in node.named_children[:1]:
                    names, guess = self.reads(child)
                    self.ops.append(ReturnOp(tuple(names), guess))
            case "expression_statement":
                for child in node.named_children:
                    self.statement(child)
            case "for_statement":
                names, guess = self.reads(node.child_by_field_name("right"))
                self._assign_to(node.child_by_field_name("left"), tuple(names), guess)
                for child in node.named_children:
                    if child.type in ("block", "else_clause"):
                        self.statement(child)
            case "with_statement":
                for child in node.named_children:
                    if child.type == "with_clause":
                        for item in child.named_children:
                            self._with_item(item)
                    else:
                        self.statement(child)
            case _ if node.type.endswith(("_statement", "_clause")) or node.type in ("block", "module"):
                for child in node.named_children:
                    self.statement(child)
            case _:
                self.reads(node)

    def _with_item(self, item: Node) -> None:
        value = item.child_by_field_name("value")
        if value is None:
            return
        if value.type == "as_pattern":
            names, guess = self.reads(value.named_children[0])
            alias = value.child_by_field_name("alias")
            target = alias.named_children[0] if alias is not None and alias.named_children else None
            self._assign_to(target, tuple(names), guess)
        else:
            self.reads(value)

    def _target_names(self, node: Node | None) -> list[str]:
        if node is None:
            return []
        if node.type in ("identifier", "attribute"):
            dotted = _dotted(node)
            return [dotted] if dotted else []
        if node.type == "subscript":
            return self._target_names(node.child_by_field_name("value"))
        names: list[str] = []
        for child in node.named_children:
            names += self._target_names(child)
        return names

    def _assign_to(self, left: Node | None, reads: tuple[str, ...], guess: bool) -> None:
        if left is None:
            return
        multi = left.type in MULTI_TARGET_TYPES or left.type == "subscript"
        for name in self._target_names(left):
            self.ops.append(AssignOp(name, reads, guess or multi))

    def reads(self, node: Node | None) -> tuple[list[str], bool]:
        if node is None:
            return [], False
        match node.type:
            case "identifier":
                return [_text(node)], False
            case "attribute":
                dotted = _dotted(node)
                if dotted:
                    return [dotted], False
                return self.reads(node.child_by_field_name("object"))
            case "call":
                return [self._call(node)], False
            case "lambda" | "function_definition" | "class_definition":
                return [], False
            case _:
                names: list[str] = []
                guess = node.type in CONTAINER_TYPES
                for child in node.named_children:
                    child_names, child_guess = self.reads(child)
                    names += child_names
                    guess = guess or child_guess
                return names, guess

    def _call(self, node: Node) -> str:
        function = node.child_by_field_name("function")
        receiver: str | None = None
        if function.type == "identifier":
            callee = _text(function)
        elif function.type == "attribute":
            dotted = _dotted(function)
            if dotted:
                callee = dotted
                receiver = dotted.rpartition(".")[0]
            else:
                inner, _ = self.reads(function.child_by_field_name("object"))
                receiver = inner[0] if inner else None
                callee = "?." + _text(function.child_by_field_name("attribute"))
        else:
            inner, _ = self.reads(function)
            receiver = inner[0] if inner else None
            callee = "?"
        args: list[tuple[str, ...]] = []
        kwargs: list[tuple[str, tuple[str, ...]]] = []
        guess_args: set[int] = set()
        guess_kwargs: set[str] = set()
        arguments = node.child_by_field_name("arguments")
        if arguments is not None and arguments.type == "argument_list":
            for arg in arguments.named_children:
                if arg.type == "keyword_argument":
                    names, guess = self.reads(arg.child_by_field_name("value"))
                    key = _text(arg.child_by_field_name("name"))
                    kwargs.append((key, tuple(names)))
                    if guess:
                        guess_kwargs.add(key)
                else:
                    names, guess = self.reads(arg)
                    if guess:
                        guess_args.add(len(args))
                    args.append(tuple(names))
        elif arguments is not None:
            names, guess = self.reads(arguments)
            if guess:
                guess_args.add(len(args))
            args.append(tuple(names))
        target = self._temp()
        self.ops.append(
            CallOp(
                target,
                callee,
                tuple(args),
                tuple(kwargs),
                receiver,
                node.start_point[0] + 1,
                frozenset(guess_args),
                frozenset(guess_kwargs),
            )
        )
        return target


def _param_name(node: Node) -> str | None:
    if node.type == "identifier":
        return _text(node)
    inner = node.child_by_field_name("name")
    if inner is None and node.named_children:
        inner = node.named_children[0]
    return _param_name(inner) if inner is not None else None


def _decorator_name(decorator: Node) -> str:
    expr = decorator.named_children[0]
    if expr.type == "call":
        expr = expr.child_by_field_name("function")
    return _dotted(expr) or ""


def _function(node: Node, module: str, class_name: str | None, decorators: list[str], scope: str) -> Function:
    name = _text(node.child_by_field_name("name"))
    qualname = f"{scope}.{name}"
    params = [_param_name(p) for p in node.child_by_field_name("parameters").named_children]
    builder = _Builder()
    builder.statement(node.child_by_field_name("body"))
    return Function(
        qualname=qualname,
        module=module,
        name=name,
        class_name=class_name,
        params=[p for p in params if p],
        decorators=decorators,
        ops=builder.ops,
        line=node.start_point[0] + 1,
    )


def _collect(node: Node, module: str, class_name: str | None, decorators: list[str], found: list[Function]) -> None:
    match node.type:
        case "decorated_definition":
            names = [_decorator_name(d) for d in node.children if d.type == "decorator"]
            _collect(node.child_by_field_name("definition"), module, class_name, names, found)
        case "function_definition":
            scope = f"{module}.{class_name}" if class_name else module
            fn = _function(node, module, class_name, decorators, scope)
            found.append(fn)
            _collect_nested(node.child_by_field_name("body"), module, fn.qualname, found)
        case "class_definition":
            name = _text(node.child_by_field_name("name"))
            for child in node.child_by_field_name("body").children:
                _collect(child, module, name, [], found)
        case _ if node.type.endswith(("_statement", "_clause")) or node.type == "block":
            for child in node.named_children:
                _collect(child, module, class_name, decorators, found)


def _collect_nested(node: Node, module: str, outer: str, found: list[Function], decorators: list[str] | None = None) -> None:
    match node.type:
        case "decorated_definition":
            names = [_decorator_name(d) for d in node.children if d.type == "decorator"]
            _collect_nested(node.child_by_field_name("definition"), module, outer, found, names)
        case "function_definition":
            fn = _function(node, module, None, decorators or [], f"{outer}.<locals>")
            found.append(fn)
            _collect_nested(node.child_by_field_name("body"), module, fn.qualname, found)
        case "class_definition":
            return
        case _:
            for child in node.named_children:
                _collect_nested(child, module, outer, found)


def extract_functions(root: Node, module: str) -> list[Function]:
    found: list[Function] = []
    for child in root.named_children:
        _collect(child, module, None, [], found)
    top = _Builder()
    for child in root.named_children:
        top.statement(child)
    if top.ops:
        found.append(Function(f"{module}.<module>", module, "<module>", None, [], [], top.ops, 1))
    return found

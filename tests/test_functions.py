from textwrap import dedent

from archscan.graph import AssignOp, CallOp, ReturnOp


def test_call_hoisting_and_assignment(build):
    project = build({
        "app/__init__.py": "",
        "app/main.py": dedent("""\
            import os

            def main():
                x = helper(os.getenv("K"))
                return x
            """),
    })
    fn = project.function("app.main.main")
    assert fn.params == []
    assert fn.ops == [
        CallOp("$t1", "os.getenv", ((),), (), "os", 4),
        CallOp("$t2", "helper", (("$t1",),), (), None, 4),
        AssignOp("x", ("$t2",)),
        ReturnOp(("x",)),
    ]


def test_method_params_decorators_and_receiver(build):
    project = build({
        "app/__init__.py": "",
        "app/svc.py": dedent("""\
            class Svc:
                @route("/x")
                def run(self, a, b: int = 1, *rest, **kw):
                    self.v = Path(a).read_text(encoding=b)
            """),
    })
    fn = project.function("app.svc.Svc.run")
    assert fn.class_name == "Svc"
    assert fn.params == ["self", "a", "b", "rest", "kw"]
    assert fn.decorators == ["route"]
    assert fn.ops == [
        CallOp("$t1", "Path", (("a",),), (), None, 4),
        CallOp("$t2", "?.read_text", (), (("encoding", ("b",)),), "$t1", 4),
        AssignOp("self.v", ("$t2",)),
    ]


def test_module_level_code_and_control_flow(build):
    project = build({
        "s.py": dedent("""\
            import sys
            for a in sys.argv:
                print(a)
            with open(a) as fh:
                data = fh.read()
            """),
    })
    assert project.function("s.<module>").ops == [
        AssignOp("a", ("sys.argv",)),
        CallOp("$t1", "print", (("a",),), (), None, 3),
        CallOp("$t2", "open", (("a",),), (), None, 4),
        AssignOp("fh", ("$t2",)),
        CallOp("$t3", "fh.read", (), (), "fh", 5),
        AssignOp("data", ("$t3",)),
    ]


def test_containers_and_subscripts_are_guesses(build):
    project = build({
        "g.py": dedent("""\
            def f(a, b):
                x, y = a, b
                z = a[0]
                return [z]
            """),
    })
    assert project.function("g.f").ops == [
        AssignOp("x", ("a", "b"), True),
        AssignOp("y", ("a", "b"), True),
        AssignOp("z", ("a",), True),
        ReturnOp(("z",), True),
    ]


def test_functions_in_else_and_except_branches_are_extracted(build):
    project = build({
        "c.py": dedent("""\
            try:
                import x
            except ImportError:
                def from_except():
                    return 1
            if FLAG:
                pass
            else:
                def from_else():
                    return 2
            """),
    })
    assert project.has_function("c.from_except")
    assert project.has_function("c.from_else")


def test_container_and_subscript_arguments_are_flagged(build):
    project = build({
        "g.py": dedent("""\
            def m(a, b, d):
                f([a], b, k=d["x"])
            """),
    })
    call = next(op for op in project.function("g.m").ops if isinstance(op, CallOp))
    assert call.guess_args == frozenset({0})
    assert call.guess_kwargs == frozenset({"k"})


def test_nested_functions_are_registered_with_locals_qualnames(build):
    project = build({
        "m.py": dedent("""\
            class C:
                def method(self):
                    def inner(a):
                        def deeper():
                            return 1
                        return a
            """),
    })
    inner = project.function("m.C.method.<locals>.inner")
    assert inner.class_name is None
    assert inner.params == ["a"]
    assert project.has_function("m.C.method.<locals>.inner.<locals>.deeper")


def test_comprehension_if_clause_reads_are_tracked(build):
    project = build({
        "app/__init__.py": "",
        "app/main.py": dedent("""\
            import os

            def f(items):
                return [x for x in items if check(os.environ["Z"])]
            """),
    })
    fn = project.function("app.main.f")
    call = next(op for op in fn.ops if isinstance(op, CallOp) and op.callee == "check")
    assert call.args == (("os.environ",),)


def test_redefined_method_keeps_the_first_definition(build):
    project = build({
        "m.py": dedent("""\
            class C:
                @property
                def value(self):
                    return 1

                @value.setter
                def value(self, v):
                    self._v = v
            """),
    })
    assert project.methods_named("value") == ["m.C.value"]
    assert project.function("m.C.value").params == ["self"]

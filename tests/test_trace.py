from textwrap import dedent

from archscan.callgraph import build_call_graph
from archscan.catalog import load_catalog
from archscan.trace import trace


def run_trace(project, only=None):
    build_call_graph(project)
    return trace(project, load_catalog(), only=only)


def test_env_reaches_subprocess_through_two_functions(build, flow_files):
    result = run_trace(build(flow_files))
    findings = result.traces["env"].findings
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.source, finding.sink, finding.sink_call) == ("env", "process", "subprocess.run")
    assert (finding.function, finding.line) == ("app.runner.run", 4)
    assert finding.path == ("app.main.main", "app.runner.run")
    assert finding.certain is True


def test_reached_functions_and_edges(build, flow_files):
    env = run_trace(build(flow_files)).traces["env"]
    assert env.functions["app.main.main"] is True
    assert env.functions["app.runner.run"] is True
    assert "app.other.idle" not in env.functions
    assert env.edges[("app.main.main", "app.runner.run")] is True


def test_unresolved_call_makes_the_path_a_guess(build):
    project = build({
        "g.py": dedent("""\
            import os

            def f():
                v = str(os.getenv("K"))
                eval(v)
            """),
    })
    finding = run_trace(project).traces["env"].findings[0]
    assert finding.sink == "process"
    assert finding.certain is False


def test_class_attribute_flow_is_a_guess(build):
    project = build({
        "job.py": dedent("""\
            import os
            import subprocess

            class Job:
                def __init__(self):
                    self.cmd = os.getenv("C")

                def run(self):
                    subprocess.run(self.cmd)
            """),
    })
    finding = run_trace(project).traces["env"].findings[0]
    assert finding.function == "job.Job.run"
    assert finding.certain is False


def test_decorated_handler_parameters_are_network_sources(build):
    project = build({
        "web.py": dedent("""\
            import subprocess
            from fastapi import FastAPI

            app = FastAPI()

            @app.get("/run")
            def run(cmd):
                subprocess.run(cmd)
            """),
    })
    findings = run_trace(project).traces["network"].findings
    assert [(f.sink, f.certain) for f in findings] == [("process", True)]


def test_recursion_terminates(build):
    project = build({
        "r.py": dedent("""\
            import os

            def f(x, n):
                if n:
                    return f(x, n - 1)
                return x

            def g():
                eval(f(os.getenv("A"), 3))
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert [(f.sink, f.certain) for f in findings] == [("process", True)]


def test_only_limits_the_result_to_one_kind(build, flow_files):
    result = run_trace(build(flow_files), only="env")
    assert list(result.traces) == ["env"]


def test_long_call_chain_converges(build):
    lines = ["import os", "import subprocess", ""]
    for i in range(25):
        lines += [f"def f{i}(v):", f"    return f{i + 1}(v)", ""]
    lines += ["def f25(v):", "    subprocess.run(v)", ""]
    lines += ["def start():", '    f0(os.getenv("X"))', ""]
    result = run_trace(build({"chain.py": "\n".join(lines)}))
    assert result.converged is True
    assert len(result.traces["env"].findings) == 1


def test_env_survives_loop_carried_assignments(build):
    project = build({
        "loop.py": dedent("""\
            import os
            import subprocess

            def main(flag):
                while flag:
                    subprocess.run(z0)
                    z0 = z1
                    z1 = os.getenv("X")
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert [(f.sink, f.function) for f in findings] == [("process", "loop.main")]


GUESS_HEAD = dedent("""\
    import os
    import subprocess

    def deep(v):
        subprocess.run(v)

    def tail(v):
        deep(v)
""")
GUESS_RUNNER = dedent("""\
    class Runner:
        def mid(self, x):
            tail(x)
""")
GUESS_CALLERS = dedent("""\
    def outside(obj):
        obj.mid(os.getenv("A"))

    def direct():
        tail(os.getenv("B"))
""")


def test_guessed_visit_does_not_hide_certain_visit(build):
    for parts in (
        (GUESS_HEAD, GUESS_RUNNER, GUESS_CALLERS),
        (GUESS_HEAD, GUESS_CALLERS, GUESS_RUNNER),
    ):
        env = run_trace(build({"t.py": "\n\n".join(parts)})).traces["env"]
        assert env.functions["t.tail"] is True
        assert env.functions["t.deep"] is True
        assert env.edges[("t.tail", "t.deep")] is True


def test_keyword_argument_passes_through(build):
    project = build({
        "k.py": dedent("""\
            import os
            import subprocess

            def runner(cmd):
                subprocess.run(cmd)

            def start():
                runner(cmd=os.getenv("X"))
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert [(f.function, f.certain) for f in findings] == [("k.runner", True)]


def test_sink_without_source_has_no_finding(build):
    project = build({
        "n.py": dedent("""\
            import subprocess

            def f():
                cmd = "ls"
                subprocess.run(cmd)
            """),
    })
    result = run_trace(project)
    assert all(not t.findings for t in result.traces.values())


def test_container_argument_is_a_guess(build):
    project = build({
        "c.py": dedent("""\
            import os
            import subprocess

            def listed():
                cmd = os.getenv("X")
                subprocess.run([cmd, "-l"])

            def plain():
                cmd = os.getenv("X")
                subprocess.run(cmd)
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert {f.function: f.certain for f in findings} == {"c.listed": False, "c.plain": True}


def test_finding_path_has_no_repeated_function(build):
    project = build({
        "m.py": dedent("""\
            import subprocess
            import sys

            def echo(x):
                return x

            def main():
                a = sys.argv
                b = echo(a)
                subprocess.run(b)
            """),
    })
    findings = run_trace(project).traces["cli"].findings
    assert findings
    for f in findings:
        assert len(set(f.path)) == len(f.path)


def test_two_callers_of_one_sink_are_two_findings(build):
    project = build({
        "m.py": dedent("""\
            import os
            import subprocess

            def sink(v):
                subprocess.run(v)

            def one():
                sink(os.getenv("A"))

            def two():
                sink(os.getenv("A"))
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert len(findings) == 2
    assert len({f.path for f in findings}) == 2


def test_two_sink_calls_on_one_line_are_two_findings(build):
    project = build({
        "m.py": dedent("""\
            import os
            import subprocess

            def f(flag):
                v = os.getenv("A")
                subprocess.run(v) if flag else os.system(v)
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert {f.sink_call for f in findings} == {"subprocess.run", "os.system"}
    assert len(findings) == 2


def test_chained_assignment_is_tracked(build):
    project = build({
        "m.py": dedent("""\
            import os
            import subprocess

            def f():
                a = b = os.environ["X"]
                subprocess.run(b)
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert findings
    assert findings[0].sink_call == "subprocess.run"


def test_comprehension_variable_is_tracked(build):
    project = build({
        "m.py": dedent("""\
            import os
            import subprocess

            def f():
                [subprocess.run(x) for x in os.environ["Y"].split(",")]
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert findings
    assert findings[0].certain is False


def test_nested_function_flow_is_reported(build):
    project = build({
        "m.py": dedent("""\
            import os
            import subprocess

            def outer():
                def inner():
                    subprocess.run(os.getenv("CMD"))
            """),
    })
    findings = run_trace(project).traces["env"].findings
    assert [f.function for f in findings] == ["m.outer.<locals>.inner"]

from textwrap import dedent

from archscan.callgraph import build_call_graph, qualify


def test_qualify_expands_the_head_name():
    assert qualify("np.load", {"np": "numpy"}) == "numpy.load"
    assert qualify("getenv", {"getenv": "os.getenv"}) == "os.getenv"
    assert qualify("open", {}) == "open"


def test_resolves_imports_methods_and_constructors(build):
    project = build({
        "app/__init__.py": "",
        "app/util.py": "def helper(x):\n    return x\n",
        "app/model.py": dedent("""\
            class Model:
                def __init__(self, cfg):
                    self.cfg = cfg

                def run(self):
                    return self.step()

                def step(self):
                    return 1
            """),
        "app/main.py": dedent("""\
            from app import util
            from app.util import helper as h
            from app.model import Model

            def main():
                h(1)
                util.helper(2)
                m = Model(3)
                m.run()
            """),
    })
    build_call_graph(project)
    edges = {(a, b): d["guess"] for a, b, d in project.calls.edges(data=True)}
    assert edges[("app.main.main", "app.util.helper")] is False
    assert edges[("app.main.main", "app.model.Model.__init__")] is False
    assert edges[("app.model.Model.run", "app.model.Model.step")] is False
    assert edges[("app.main.main", "app.model.Model.run")] is True


def test_sibling_script_imports_and_reexports(build):
    project = build({
        "pkg/__init__.py": "from pkg.core import work\n",
        "pkg/core.py": "def work():\n    pass\n",
        "scripts/_common.py": "def load():\n    pass\n",
        "scripts/run.py": dedent("""\
            from _common import load
            from pkg import work

            def go():
                load()
                work()
            """),
    })
    build_call_graph(project)
    edges = {(a, b): d["guess"] for a, b, d in project.calls.edges(data=True)}
    assert edges[("scripts.run.go", "scripts._common.load")] is False
    assert edges[("scripts.run.go", "pkg.core.work")] is False

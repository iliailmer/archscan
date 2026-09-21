from pathlib import Path

from archscan.scan.python import scan


def make(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


def test_import_graph(tmp_path):
    make(tmp_path, {
        "app/__init__.py": "",
        "app/main.py": "import os\nfrom app import db\nfrom .util import helper\nif __name__ == '__main__':\n    pass\n",
        "app/db.py": "import subprocess\nsubprocess.run(['ls'])\neval('1')\n",
        "app/util.py": "def helper(): ...\n",
    })
    project = scan(tmp_path)
    assert set(project.graph.edges) == {("app.main", "app.db"), ("app.main", "app.util")}
    main = project.module("app.main")
    assert main.external_imports == ["os"]
    assert main.entry_points == ["__main__"]
    assert len(project.module("app.db").risks) == 2


def test_sibling_script_import(tmp_path):
    make(tmp_path, {
        "scripts/_common.py": "",
        "scripts/train.py": "from _common import load\nimport requests\n",
    })
    project = scan(tmp_path)
    assert set(project.graph.edges) == {("scripts.train", "scripts._common")}
    assert project.module("scripts.train").external_imports == ["requests"]

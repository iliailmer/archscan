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


def _write(root, files):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def test_noisy_directories_are_skipped_by_default(tmp_path):
    from archscan.scan.python import scan

    _write(tmp_path, {f"{d}/{f}.py": "" for d, f in [("docs", "x"), ("examples", "y"), ("benchmarks", "z"), ("doc", "w")]})
    _write(tmp_path, {"keep.py": ""})
    project = scan(tmp_path)
    assert [m.name for m in project.modules()] == ["keep"]
    assert project.skipped == {"docs": 1, "examples": 1, "benchmarks": 1, "doc": 1}


def test_settings_keep_and_skip(tmp_path):
    from archscan.scan.python import scan
    from archscan.settings import load_scan_settings

    _write(tmp_path, {"examples/y.py": "", "extra/q.py": "", "a.py": "",
                      "archscan.toml": '[scan]\nskip = ["extra"]\nkeep = ["examples"]\n'})
    names = {m.name for m in scan(tmp_path, skip=load_scan_settings(tmp_path)).modules()}
    assert names == {"examples.y", "a"}


def test_missing_settings_file_gives_defaults(tmp_path):
    from archscan.settings import DEFAULT_SKIP_DIRS, load_scan_settings

    assert load_scan_settings(tmp_path) == set(DEFAULT_SKIP_DIRS)


def test_pyproject_scripts_become_entry_points(tmp_path):
    make(tmp_path, {
        "app/__init__.py": "",
        "app/main.py": "def main():\n    pass\n",
        "pyproject.toml": '[project.scripts]\napp = "app.main:main"\n',
    })
    project = scan(tmp_path)
    assert "script app -> main" in project.module("app.main").entry_points


def test_pyproject_scripts_resolve_src_layout_suffix(tmp_path):
    make(tmp_path, {
        "src/app/__init__.py": "",
        "src/app/main.py": "def main():\n    pass\n",
        "pyproject.toml": '[project.scripts]\napp = "app.main:main"\n',
    })
    project = scan(tmp_path)
    assert "script app -> main" in project.module("src.app.main").entry_points


def test_pyproject_missing_or_unparseable_is_ignored(tmp_path):
    make(tmp_path, {"a.py": "", "pyproject.toml": "[project\n"})
    project = scan(tmp_path)
    assert project.module("a").entry_points == []


def test_pyproject_scripts_as_a_list_is_ignored(tmp_path):
    make(tmp_path, {
        "a.py": "def a():\n    return 1\n",
        "pyproject.toml": '[project]\nscripts = ["a", "b"]\n',
    })
    project = scan(tmp_path)
    assert project.module("a").entry_points == []


def test_pyproject_non_table_project_is_ignored(tmp_path):
    make(tmp_path, {
        "a.py": "def a():\n    return 1\n",
        "pyproject.toml": 'project = "x"\n',
    })
    project = scan(tmp_path)
    assert project.module("a").entry_points == []


def test_pyproject_non_string_script_target_is_ignored(tmp_path):
    make(tmp_path, {
        "a.py": "def a():\n    return 1\n",
        "pyproject.toml": "[project.scripts]\napp = 5\n",
    })
    project = scan(tmp_path)
    assert project.module("a").entry_points == []


def test_pyproject_bad_entry_next_to_good_entry_is_still_detected(tmp_path):
    make(tmp_path, {
        "app/__init__.py": "",
        "app/main.py": "def main():\n    pass\n",
        "pyproject.toml": '[project.scripts]\napp = "app.main:main"\nbad = 5\n',
    })
    project = scan(tmp_path)
    assert "script app -> main" in project.module("app.main").entry_points


def test_dunder_main_file_is_an_entry_point(tmp_path):
    make(tmp_path, {
        "pkg/__init__.py": "",
        "pkg/__main__.py": "print('hi')\n",
    })
    project = scan(tmp_path)
    assert "__main__" in project.module("pkg.__main__").entry_points


def test_malformed_settings_file_raises(tmp_path):
    import tomllib

    import pytest

    from archscan.settings import load_scan_settings

    (tmp_path / "archscan.toml").write_text("[scan\n")
    with pytest.raises(tomllib.TOMLDecodeError):
        load_scan_settings(tmp_path)

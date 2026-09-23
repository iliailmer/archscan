import textwrap

import pytest

from archscan.scan.python import scan


@pytest.fixture
def build(tmp_path):
    def _build(files: dict[str, str]):
        for rel, text in files.items():
            path = tmp_path / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return scan(tmp_path)

    return _build


@pytest.fixture
def flow_files() -> dict[str, str]:
    return {
        "app/__init__.py": "",
        "app/main.py": textwrap.dedent("""\
            import os
            from app.runner import run

            def main():
                cmd = os.getenv("CMD")
                run(cmd)
            """),
        "app/runner.py": textwrap.dedent("""\
            import subprocess

            def run(cmd):
                subprocess.run(cmd, shell=True)
            """),
        "app/other.py": "def idle():\n    return 1\n",
    }

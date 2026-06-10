"""Tests for scripts/compile_requirements.py."""
from pathlib import Path

from scripts import compile_requirements


REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"


def test_pyproject_loads():
    data = compile_requirements._load_pyproject(PYPROJECT)
    assert "project" in data


def test_main_invokes_pip_compile(tmp_path, mocker):
    (tmp_path / "pyproject.toml").write_bytes(PYPROJECT.read_bytes())
    run_mock = mocker.patch("scripts.compile_requirements.subprocess.run")
    run_mock.return_value.returncode = 0

    rc = compile_requirements.main(repo_root=tmp_path)

    assert rc == 0
    run_mock.assert_called_once_with(
        [
            "pip-compile",
            "pyproject.toml",
            "--extra",
            "dev",
            "--output-file",
            "requirements.txt",
        ],
        cwd=tmp_path,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_main_propagates_pip_compile_failure(tmp_path, mocker):
    (tmp_path / "pyproject.toml").write_bytes(PYPROJECT.read_bytes())
    run_mock = mocker.patch("scripts.compile_requirements.subprocess.run")
    run_mock.return_value.returncode = 2

    rc = compile_requirements.main(repo_root=tmp_path)

    assert rc == 2

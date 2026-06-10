"""Compile requirements.txt from pyproject.toml via pip-compile."""
from pathlib import Path
import subprocess
import tomllib


def _load_pyproject(pyproject_path: Path) -> dict:
    with pyproject_path.open("rb") as f:
        return tomllib.load(f)


def main(repo_root: Path | None = None) -> int:
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent
    pyproject_path = repo_root / "pyproject.toml"
    output_path = repo_root / "requirements.txt"

    proc = subprocess.run(
        [
            "pip-compile",
            "pyproject.toml",
            "--extra",
            "dev",
            "--output-file",
            "requirements.txt",
        ],
        cwd=repo_root,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        print("pip-compile failed; requirements.txt was not updated")
        return proc.returncode
    print(f"Wrote {output_path} from {pyproject_path} via pip-compile")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

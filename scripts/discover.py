"""Manifest discovery — walks local roots and identifies dependency manifests."""
import hashlib
from pathlib import Path
from typing import Iterator


# Map of filename → ecosystem identifier
MANIFEST_ECOSYSTEM = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "python",
    "poetry.lock": "python",
    "Pipfile.lock": "python",
    "uv.lock": "python",
    "Cargo.lock": "rust",
    "go.sum": "go",
    "Gemfile.lock": "ruby",
    "composer.lock": "php",
    "pom.xml": "java",
}

DEFAULT_EXCLUDES = frozenset({
    ".git", "node_modules", ".venv", "__pycache__", "dist", "build",
    ".next", "target", ".nuxt", "vendor",
})


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def discover_manifests(
    roots: list[dict],
    max_depth: int = 4,
    max_files: int = 10000,
) -> Iterator[dict]:
    """Walk a list of root specs and yield manifest records.

    Each yielded dict has:
        target: the root or project name
        path:   absolute path to the manifest
        ecosystem: 'npm' | 'python' | 'rust' | 'go' | 'ruby' | 'php' | 'java'
        manifest_hash: sha256 of file contents
        tier: int
    """
    file_count = 0
    for root in roots:
        root_path = Path(root["path"])
        if not root_path.exists():
            continue
        excludes = set(root.get("exclude", DEFAULT_EXCLUDES))
        tier = root.get("tier", 1)
        for path in _walk_with_depth(root_path, excludes, max_depth):
            file_count += 1
            if file_count > max_files:
                return
            if path.name in MANIFEST_ECOSYSTEM:
                yield {
                    "target": root_path.name,
                    "path": str(path),
                    "ecosystem": MANIFEST_ECOSYSTEM[path.name],
                    "manifest_hash": _hash_file(path),
                    "tier": tier,
                }


def _walk_with_depth(root: Path, excludes: set, max_depth: int) -> Iterator[Path]:
    def walk(p: Path, depth: int):
        if depth > max_depth:
            return
        try:
            for entry in p.iterdir():
                if entry.name in excludes:
                    continue
                if entry.is_dir():
                    yield from walk(entry, depth + 1)
                else:
                    yield entry
        except PermissionError:
            pass
    yield from walk(root, 0)

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
    ".next", "target", ".nuxt", "vendor", "fixtures",
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


def discover_manifests_full(
    roots: list[dict],
    projects: list[dict],
    tier_filter: set[int] | None = None,
    max_depth: int = 4,
    max_files: int = 10000,
) -> Iterator[dict]:
    """Walk both roots[] (recursive walk) and projects[] (explicit single-project paths).

    Args:
        roots: list of root specs (path, tier, exclude). Walked recursively.
        projects: list of project specs (path, name, tier). Each is scanned
            as a standalone single-project (not walked further than max_depth=2).
        tier_filter: if provided, only entries with tier in this set are scanned.
        max_depth: walk depth for roots
        max_files: total file count cap across all walks

    Yields the same dict shape as discover_manifests().
    """
    # Filter roots by tier
    if tier_filter is not None:
        filtered_roots = [r for r in roots if r.get("tier", 1) in tier_filter]
    else:
        filtered_roots = list(roots)
    yield from discover_manifests(filtered_roots, max_depth=max_depth, max_files=max_files)

    # Filter projects by tier and scan each as a shallow root
    if tier_filter is not None:
        filtered_projects = [p for p in projects if p.get("tier", 1) in tier_filter]
    else:
        filtered_projects = list(projects)

    for proj in filtered_projects:
        proj_path = Path(proj["path"])
        if not proj_path.exists():
            continue
        # Walk the project shallowly (depth 2 — top + 1 subdir)
        for path in _walk_with_depth(proj_path, set(DEFAULT_EXCLUDES), max_depth=2):
            if path.name in MANIFEST_ECOSYSTEM:
                yield {
                    "target": proj.get("name", proj_path.name),
                    "path": str(path),
                    "ecosystem": MANIFEST_ECOSYSTEM[path.name],
                    "manifest_hash": _hash_file(path),
                    "tier": proj.get("tier", 1),
                }

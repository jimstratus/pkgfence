"""Tests for local manifest discovery."""
from pathlib import Path
from scripts.discover import discover_manifests


def test_discover_npm_in_root(tmp_path):
    """Walks a parent dir, finds package-lock.json under sub-projects."""
    proj1 = tmp_path / "proj1"
    proj1.mkdir()
    (proj1 / "package-lock.json").write_text('{"name":"proj1","lockfileVersion":3}')

    proj2 = tmp_path / "proj2"
    proj2.mkdir()
    (proj2 / "package-lock.json").write_text('{"name":"proj2","lockfileVersion":3}')

    results = list(discover_manifests([{"path": str(tmp_path), "tier": 1}]))
    assert len(results) == 2
    assert {r["ecosystem"] for r in results} == {"npm"}
    assert {Path(r["path"]).parent.name for r in results} == {"proj1", "proj2"}


def test_discover_skips_excluded_dirs(tmp_path):
    """node_modules and .git are excluded."""
    nm = tmp_path / "node_modules" / "subpkg"
    nm.mkdir(parents=True)
    (nm / "package-lock.json").write_text("{}")
    git = tmp_path / ".git" / "subdir"
    git.mkdir(parents=True)
    (git / "package.json").write_text("{}")

    results = list(discover_manifests([{
        "path": str(tmp_path), "tier": 1,
        "exclude": ["node_modules", ".git"],
    }]))
    assert len(results) == 0


def test_discover_python(tmp_path):
    proj = tmp_path / "pyproj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("django==4.2.0\n")
    results = list(discover_manifests([{"path": str(tmp_path), "tier": 1}]))
    assert len(results) == 1
    assert results[0]["ecosystem"] == "python"


def test_discover_explicit_project(tmp_path):
    """projects[] entries are scanned as standalone projects, not walked."""
    from scripts.discover import discover_manifests_full
    proj = tmp_path / "myproj"
    proj.mkdir()
    (proj / "package-lock.json").write_text('{}')

    results = list(discover_manifests_full(
        roots=[],
        projects=[{"path": str(proj), "name": "myproj", "tier": 1}],
    ))
    assert len(results) == 1
    assert results[0]["target"] == "myproj"
    assert results[0]["ecosystem"] == "npm"


def test_discover_tier_filter(tmp_path):
    """Tier filter only scans matching-tier roots."""
    from scripts.discover import discover_manifests_full
    proj1 = tmp_path / "tier1-proj"
    proj1.mkdir()
    (proj1 / "package-lock.json").write_text('{}')
    proj2 = tmp_path / "tier2-proj"
    proj2.mkdir()
    (proj2 / "package-lock.json").write_text('{}')

    # Only scan tier 1
    results = list(discover_manifests_full(
        roots=[
            {"path": str(proj1), "tier": 1},
            {"path": str(proj2), "tier": 2},
        ],
        projects=[],
        tier_filter={1},
    ))
    assert len(results) == 1
    # Should be the tier-1 root
    assert "tier1-proj" in results[0]["path"]

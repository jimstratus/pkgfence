"""Tests for CDN/SRI scanner correctness."""
from pathlib import Path

import sys

import pytest

from scripts.discover import DEFAULT_EXCLUDES
from scripts.scan_cdn import _walk_pruned, scan_cdn_sri


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_flags_script_without_integrity(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js"></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "CDN-MISSING-SRI"


def test_skips_script_with_integrity_same_tag(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js" '
        'integrity="sha384-abc123" crossorigin="anonymous"></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert findings == []


def test_integrity_before_src_still_counts(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<script integrity="sha384-abc" '
        'src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js"></script>',
    )
    assert scan_cdn_sri(tmp_path, "test") == []


def test_does_not_leak_integrity_from_neighbor_tag(tmp_path):
    """Regression: integrity on a nearby tag must not suppress a missing-SRI finding."""
    _write(
        tmp_path,
        "index.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/bad.js"></script>\n'
        '<script src="https://unpkg.com/ok.js" integrity="sha384-x"></script>\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "bad.js" in findings[0]["description"]
    assert "ok.js" not in findings[0]["description"]


def test_skips_preconnect_and_dns_prefetch_links(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<link rel="preconnect" href="https://cdn.jsdelivr.net">\n'
        '<link rel="dns-prefetch" href="https://unpkg.com">\n'
        '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/x.css">\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "x.css" in findings[0]["description"]


def test_flags_stylesheet_and_preload_without_integrity(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/x.css">\n'
        '<link rel="preload" as="script" href="https://unpkg.com/y.js">\n'
        '<link rel="modulepreload" href="https://cdn.jsdelivr.net/npm/z.js">\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 3


def test_default_excludes_skip_node_modules(tmp_path):
    _write(
        tmp_path,
        "node_modules/pkg/index.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/x.js"></script>',
    )
    _write(
        tmp_path,
        "app.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/y.js"></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "y.js" in findings[0]["description"]
    # Explicit empty excludes opts out of the default set.
    all_findings = scan_cdn_sri(tmp_path, "test", excludes=set())
    assert len(all_findings) == 2
    assert "node_modules" in DEFAULT_EXCLUDES  # lock the default-excludes contract


def test_data_rel_does_not_trigger_sri_requirement(tmp_path):
    """data-rel must not be treated as the HTML rel attribute."""
    _write(
        tmp_path,
        "index.html",
        '<link data-rel="stylesheet" href="https://cdn.jsdelivr.net/npm/x.css">\n'
        '<link rel="stylesheet" href="https://unpkg.com/y.css">\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "y.css" in findings[0]["description"]


def test_unquoted_rel_stylesheet_is_flagged(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<link rel=stylesheet href="https://unpkg.com/a.css">\n'
        '<link rel=preconnect href="https://cdn.jsdelivr.net">\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "a.css" in findings[0]["description"]


def test_excludes_are_relative_to_scan_root(tmp_path):
    """A scan root whose path contains a default-exclude name must still scan."""
    root = tmp_path / "build" / "project"
    _write(
        root,
        "index.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/x.js"></script>',
    )
    findings = scan_cdn_sri(root, "test")
    assert len(findings) == 1
    # Nested exclude under root still skipped
    _write(
        root,
        "dist/index.html",
        '<script src="https://unpkg.com/y.js"></script>',
    )
    findings = scan_cdn_sri(root, "test")
    assert len(findings) == 1
    assert "x.js" in findings[0]["description"]


def test_data_meta_integrity_does_not_suppress_missing_sri(tmp_path):
    """Quoted value text like integrity=true must not count as an integrity attr."""
    _write(
        tmp_path,
        "index.html",
        '<script data-meta="integrity=true" '
        'src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js"></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "CDN-MISSING-SRI"


def test_data_meta_rel_stylesheet_does_not_flag_link_without_rel(tmp_path):
    """Quoted rel='stylesheet' inside another attr must not make the link SRI-eligible."""
    _write(
        tmp_path,
        "index.html",
        '<link data-meta="rel=\'stylesheet\'" href="https://cdn.jsdelivr.net/npm/x.css">\n'
        '<link rel="stylesheet" href="https://unpkg.com/y.css">\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "y.css" in findings[0]["description"]
    assert "x.css" not in findings[0]["description"]


def test_custom_exclude_skips_named_dirs_not_defaults(tmp_path):
    """Custom exclude set replaces defaults: only named dirs are pruned."""
    _write(
        tmp_path,
        "vendor/lib/index.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/v.js"></script>',
    )
    _write(
        tmp_path,
        "node_modules/pkg/index.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/n.js"></script>',
    )
    _write(
        tmp_path,
        "app.html",
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/a.js"></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test", excludes={"vendor"})
    assert len(findings) == 2
    descs = " ".join(f["description"] for f in findings)
    assert "a.js" in descs
    assert "n.js" in descs
    assert "v.js" not in descs


def test_walk_prunes_excluded_dirs_before_descent(tmp_path):
    """Excluded directory names must not be entered (not merely filtered after rglob)."""
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.html").write_text("<html></html>", encoding="utf-8")
    (tmp_path / "app.html").write_text("<html></html>", encoding="utf-8")

    entered: list[str] = []
    real_iterdir = Path.iterdir

    def tracking_iterdir(self: Path):
        entered.append(self.name)
        return real_iterdir(self)

    # Patch Path.iterdir for the duration of the walk.
    original = Path.iterdir
    try:
        Path.iterdir = tracking_iterdir  # type: ignore[method-assign]
        paths = list(_walk_pruned(tmp_path, {"node_modules"}))
    finally:
        Path.iterdir = original  # type: ignore[method-assign]

    assert any(p.name == "app.html" for p in paths)
    assert not any("node_modules" in p.parts for p in paths)
    # Walk entered tmp_path but never descended into node_modules.
    assert tmp_path.name in entered or entered  # root was listed
    assert "node_modules" not in entered
    assert "pkg" not in entered


def test_duplicate_integrity_keeps_first_empty(tmp_path):
    """Browsers keep the first integrity; empty/boolean first still means missing SRI."""
    _write(
        tmp_path,
        "index.html",
        '<script src="https://unpkg.com/a.js" integrity integrity="sha384-abc"></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "CDN-MISSING-SRI"
    assert "a.js" in findings[0]["description"]


def test_empty_integrity_value_is_missing_sri(tmp_path):
    """integrity=\"\" is present-but-empty — not valid SRI."""
    _write(
        tmp_path,
        "index.html",
        '<script src="https://unpkg.com/a.js" integrity=""></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "a.js" in findings[0]["description"]


def test_walk_does_not_follow_dir_symlink_cycle(tmp_path):
    """Ancestor directory symlink must not cause unbounded recursion."""
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    (nested / "page.html").write_text(
        '<script src="https://unpkg.com/x.js"></script>', encoding="utf-8"
    )
    # Cycle: a/b/loop -> a (ancestor)
    try:
        (nested / "loop").symlink_to(tmp_path / "a")
    except OSError as exc:
        pytest.skip(f"symlink creation requires privilege (Windows): {exc}")

    paths = list(_walk_pruned(tmp_path, set()))
    assert any(p.name == "page.html" for p in paths)
    # Symlink itself may be yielded as a non-dir entry; must not re-enter a/b.
    assert not any(p.name == "loop" and (not p.is_symlink() and p.is_dir()) for p in paths)
    # Full scan must complete (no RecursionError) and still find the CDN hit.
    findings = scan_cdn_sri(tmp_path, "test", excludes=set())
    assert len(findings) == 1
    assert "x.js" in findings[0]["description"]


def test_walk_does_not_follow_external_dir_symlink(tmp_path):
    """Directory symlink pointing outside the scan root must not be descended."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.html").write_text(
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/secret.js"></script>',
        encoding="utf-8",
    )
    root = tmp_path / "root"
    root.mkdir()
    (root / "app.html").write_text(
        '<script src="https://unpkg.com/app.js"></script>', encoding="utf-8"
    )
    try:
        (root / "escape").symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation requires privilege (Windows): {exc}")

    paths = list(_walk_pruned(root, set()))
    names = {p.name for p in paths}
    assert "app.html" in names
    assert "secret.html" not in names

    findings = scan_cdn_sri(root, "test", excludes=set())
    assert len(findings) == 1
    assert "app.js" in findings[0]["description"]
    assert "secret.js" not in findings[0]["description"]


def test_walk_handles_deep_nonsymlink_tree():
    """Iterative walk must survive depth > recursion limit without long FS paths.

    Uses a synthetic in-memory tree (avoids Windows MAX_PATH) while still
    proving the stack-based walker does not recurse into Python frames.
    """
    depth = sys.getrecursionlimit() + 50
    leaf_name = "deep.html"

    class _FakeEntry:
        """Minimal Path stand-in for _walk_pruned (name / is_symlink / is_dir / iterdir)."""

        def __init__(self, name: str, *, is_directory: bool = False, children=None):
            self.name = name
            self._is_directory = is_directory
            self._children = list(children or [])

        def is_symlink(self) -> bool:
            return False

        def is_dir(self) -> bool:
            return self._is_directory

        def iterdir(self):
            return iter(self._children)

    leaf = _FakeEntry(leaf_name)
    node = _FakeEntry("d", is_directory=True, children=[leaf])
    for _ in range(depth - 1):
        node = _FakeEntry("d", is_directory=True, children=[node])
    root = _FakeEntry("root", is_directory=True, children=[node])

    paths = list(_walk_pruned(root, set()))
    assert any(p.name == leaf_name for p in paths)
    assert len(paths) == 1

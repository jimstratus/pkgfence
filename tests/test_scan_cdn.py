"""Tests for CDN/SRI scanner correctness."""
from pathlib import Path

from scripts.discover import DEFAULT_EXCLUDES
from scripts.scan_cdn import scan_cdn_sri


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

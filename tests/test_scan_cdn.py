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
        (nested / "loop").symlink_to(tmp_path / "a", target_is_directory=True)
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
        (root / "escape").symlink_to(outside, target_is_directory=True)
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


def test_src_text_inside_other_attribute_is_ignored(tmp_path):
    _write(
        tmp_path,
        "index.html",
        "<script data-meta='src=\"https://unpkg.com/ghost.js\"'></script>\n"
        "<link rel=\"stylesheet\" data-x='href=\"https://unpkg.com/a.css\"'>",
    )
    assert scan_cdn_sri(tmp_path, "test") == []


def test_real_src_after_decoy_attribute_is_flagged(tmp_path):
    _write(
        tmp_path,
        "index.html",
        "<script data-meta='src=\"https://example.com/x.js\"' "
        "src=\"https://unpkg.com/real.js\"></script>",
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://unpkg.com/real.js" in findings[0]["description"]


def test_unquoted_cdn_src_is_flagged(tmp_path):
    _write(tmp_path, "index.html", "<script src=https://unpkg.com/a.js></script>")
    assert len(scan_cdn_sri(tmp_path, "test")) == 1


def test_quoted_cdn_src_with_internal_space_is_flagged(tmp_path):
    _write(
        tmp_path, "index.html", '<script src="https://unpkg.com/my lib.js"></script>'
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://unpkg.com/my lib.js" in findings[0]["description"]


def test_cdn_src_with_tab_newline_and_padding_is_flagged(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<script src="  https://un\tpkg.com/a\n.js \r\n"></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://unpkg.com/a.js" in findings[0]["description"]


def test_nul_in_cdn_src_is_not_treated_as_padding(tmp_path):
    # HTML replaces NUL with U+FFFD, so this never loads from unpkg.com.
    _write(
        tmp_path, "index.html", '<script src="\x00https://unpkg.com/a.js"></script>'
    )
    assert scan_cdn_sri(tmp_path, "test") == []


# --- Issue #8: URL forms browsers still fetch from the CDN ------------------


def _descs(findings) -> str:
    return " | ".join(f["description"] for f in findings)


def test_protocol_relative_script_is_flagged_as_https(tmp_path):
    _write(tmp_path, "index.html", '<script src="//unpkg.com/x.js"></script>')
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert findings[0]["purl"] == "pkg:cdn/unpkg.com"
    assert "https://unpkg.com/x.js" in findings[0]["description"]
    assert "https:////" not in findings[0]["description"]


def test_protocol_relative_stylesheet_link_is_flagged(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<link rel=stylesheet href="//cdn.jsdelivr.net/npm/x.css">\n'
        '<link rel="preconnect" href="//unpkg.com">\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://cdn.jsdelivr.net/npm/x.css" in findings[0]["description"]


def test_protocol_relative_with_integrity_is_not_flagged(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<script src="//unpkg.com/x.js" integrity="sha384-abc"></script>',
    )
    assert scan_cdn_sri(tmp_path, "test") == []


@pytest.mark.parametrize(
    "src",
    [
        "\\\\unpkg.com/x.js",  # \\unpkg.com/x.js
        "/\\unpkg.com/x.js",
        "\\/unpkg.com/x.js",
        "///unpkg.com/x.js",
    ],
)
def test_protocol_relative_slash_variants_are_flagged(tmp_path, src):
    _write(tmp_path, "index.html", f'<script src="{src}"></script>')
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://unpkg.com/x.js" in findings[0]["description"]


@pytest.mark.parametrize(
    "src",
    [
        "/unpkg.com/x.js",  # root-relative path on the page's own origin
        "unpkg.com/x.js",  # relative path
        "./unpkg.com/x.js",
        "\\unpkg.com/x.js",  # single backslash == single slash: path
        "//example.com/unpkg.com/x.js",
        "//unpkg.com.example.com/x.js",
        "//example.com/?u=//unpkg.com/x.js",
    ],
)
def test_non_cdn_relative_and_lookalike_urls_are_not_flagged(tmp_path, src):
    _write(tmp_path, "index.html", f'<script src="{src}"></script>')
    assert scan_cdn_sri(tmp_path, "test") == []


@pytest.mark.parametrize(
    "src",
    [
        "https:\\\\unpkg.com\\x.js",  # https:\\unpkg.com\x.js
        "https:/\\unpkg.com/x.js",
        "https:\\/unpkg.com/x.js",
        "https:////unpkg.com/x.js",
        "HTTPS://unpkg.com/x.js",
        "HtTpS:\\\\unpkg.com/x.js",
        "http:\\\\unpkg.com/x.js",
    ],
)
def test_backslash_extra_slash_and_scheme_case_are_flagged(tmp_path, src):
    _write(tmp_path, "index.html", f'<script src="{src}"></script>')
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert findings[0]["purl"] == "pkg:cdn/unpkg.com"
    assert "https://unpkg.com/x.js" in findings[0]["description"]


def test_backslash_stylesheet_link_is_flagged(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<link rel="stylesheet" href="https:\\\\cdn.jsdelivr.net\\npm\\x.css">',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://cdn.jsdelivr.net/npm/x.css" in findings[0]["description"]


@pytest.mark.parametrize(
    "src",
    [
        "https://un&#9;pkg.com/x.js",  # tab char ref, removed by URL parser
        "https://un&#x9;pkg.com/x.js",
        "https://un&#10;pkg.com/x.js",
        "https://un&NewLine;pkg.com/x.js",
        "https://un&Tab;pkg.com/x.js",
        "https:&#x2F;&#x2F;unpkg.com&#x2F;x.js",
        "https:&#47;&#47;unpkg.com/x.js",
        "https&colon;//unpkg.com/x.js",
        "https&#58;//unpkg.com/x.js",
        "https:&sol;&sol;unpkg.com/x.js",
        "&#104;ttps://unpkg.com/x.js",
        "&#x20;https://unpkg.com/x.js",  # decoded leading space is URL padding
        "&#47;&#47;unpkg.com/x.js",  # protocol-relative via char refs
        "https:&bsol;&bsol;unpkg.com/x.js",
        "https://unpkg&period;com/x.js",
        "https://&#117;&#110;&#112;&#107;&#103;&#46;&#99;&#111;&#109;/x.js",
    ],
)
def test_char_refs_in_src_are_decoded(tmp_path, src):
    _write(tmp_path, "index.html", f'<script src="{src}"></script>')
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1, src
    assert findings[0]["purl"] == "pkg:cdn/unpkg.com"
    assert "https://unpkg.com/x.js" in findings[0]["description"]


def test_char_refs_in_unquoted_src_are_decoded(tmp_path):
    _write(tmp_path, "index.html", "<script src=https:&#x2F;&#x2F;unpkg.com/x.js></script>")
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://unpkg.com/x.js" in findings[0]["description"]


def test_char_refs_in_link_href_and_rel_are_decoded(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<link rel="style&#115;heet" href="https:&#x2F;&#x2F;cdn.jsdelivr.net/npm/x.css">\n'
        '<link rel="pre&#99;onnect" href="https://unpkg.com">\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://cdn.jsdelivr.net/npm/x.css" in findings[0]["description"]


def test_nul_char_ref_blocks_the_fetch_like_raw_nul(tmp_path):
    # &#0; decodes to U+FFFD (not NUL), so it is never stripped as URL padding.
    _write(
        tmp_path,
        "index.html",
        '<script src="&#0;https://unpkg.com/a.js"></script>\n'
        '<script src="https://un&#0;pkg.com/b.js"></script>\n'
        '<script src="https://un\x00pkg.com/c.js"></script>\n',
    )
    assert scan_cdn_sri(tmp_path, "test") == []


def test_char_ref_decoded_integrity_counts_but_blank_does_not(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<script src="https://unpkg.com/ok.js" integrity="sha384&#45;abc"></script>\n'
        '<script src="https://unpkg.com/bad.js" integrity="&#32;"></script>\n',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "bad.js" in findings[0]["description"]


def test_legacy_named_ref_followed_by_equals_is_not_decoded_in_attribute(tmp_path):
    # HTML attribute rule: "&copy=" stays literal (it is a query string), so the
    # reported URL must not be mangled into "(c)=".
    _write(
        tmp_path,
        "index.html",
        '<script src="https://unpkg.com/x.js?a=1&copy=2&amp;b=3"></script>',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert "https://unpkg.com/x.js?a=1&copy=2&b=3" in findings[0]["description"]


def test_char_ref_text_in_other_attribute_is_ignored(tmp_path):
    _write(
        tmp_path,
        "index.html",
        "<script data-x='src=&quot;https://unpkg.com/ghost.js&quot;'></script>\n"
        '<script src="https://example.com/x.js" '
        'data-x="&#x2F;&#x2F;unpkg.com/ghost.js"></script>\n',
    )
    assert scan_cdn_sri(tmp_path, "test") == []


@pytest.mark.parametrize(
    "src",
    [
        "https://UNPKG.COM/x.js",
        "https://UnPkg.Com/x.js",
        "https://evil@unpkg.com/x.js",
        "https://user:pass@unpkg.com/x.js",
        "https://a@b@unpkg.com/x.js",
        "https://unpkg.com:443/x.js",
        "https://unpkg.com:/x.js",
        "https://unpkg.com./x.js",
        "https://UNPKG.com.:443/x.js",
        "//evil@unpkg.com:8443/x.js",
        "https://unpkg.com",
        "https://unpkg.com?x=1",
        "https://unpkg.com#frag",
        "https://un%70kg.com/x.js",  # host is percent-decoded
        "https://ｕｎｐｋｇ．ｃｏｍ/x.js",  # fullwidth: IDNA-mapped to ASCII
    ],
)
def test_host_matching_is_robust(tmp_path, src):
    _write(tmp_path, "index.html", f'<script src="{src}"></script>')
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1, src
    assert findings[0]["purl"] == "pkg:cdn/unpkg.com"


@pytest.mark.parametrize(
    "src",
    [
        "https://unpkg.com@evil.example/x.js",  # unpkg.com is userinfo here
        "https://evil.example/@unpkg.com/x.js",  # '@' in path, not authority
        "https://evil.example\\@unpkg.com/x.js",  # '\' ends the authority
        "https://evil.example?@unpkg.com/x.js",
        "https://evil.example#@unpkg.com/x.js",
        "https://notunpkg.com/x.js",
        "https://unpkg.com.evil.example/x.js",
        "https://unpkg.co/x.js",
        "https://unpkg.com../x.js",
        "ftp://unpkg.com/x.js",
        "javascript://unpkg.com/%0Aalert(1)",
        "data:text/javascript,//unpkg.com/x.js",
        "https:",
        "https://",
        "//",
        "https://[::1]/unpkg.com/x.js",
    ],
)
def test_non_cdn_hosts_are_not_flagged(tmp_path, src):
    _write(tmp_path, "index.html", f'<script src="{src}"></script>')
    assert scan_cdn_sri(tmp_path, "test") == [], src


def test_userinfo_cdn_link_stylesheet_is_flagged(tmp_path):
    _write(
        tmp_path,
        "index.html",
        '<link rel="stylesheet" href="https://x@CDN.JSDELIVR.NET.:443/npm/x.css">',
    )
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1
    assert findings[0]["purl"] == "pkg:cdn/cdn.jsdelivr.net"


@pytest.mark.parametrize(
    "src",
    ["https:unpkg.com/x.js", "https:/unpkg.com/x.js", "http:\\unpkg.com/x.js"],
)
def test_special_scheme_with_fewer_than_two_slashes_is_flagged(tmp_path, src):
    # WHATWG: when the document's scheme differs (http page, file:// preview,
    # no base) these parse as authority "unpkg.com"; flag conservatively.
    _write(tmp_path, "index.html", f'<script src="{src}"></script>')
    findings = scan_cdn_sri(tmp_path, "test")
    assert len(findings) == 1, src
    assert "https://unpkg.com/x.js" in findings[0]["description"]

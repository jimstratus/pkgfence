"""Build/parse round-trip for the report frontmatter format."""
from scripts.lib.frontmatter import build_frontmatter, parse_frontmatter


def test_frontmatter_round_trips():
    data = {"run_id": "r1", "findings_by_severity": {"critical": 2, "info": 0},
            "ssh_targets": ["bespin"]}
    text = build_frontmatter(data) + "# Scan Report\nbody\n"
    assert parse_frontmatter(text) == data


def test_parse_frontmatter_no_block_returns_empty():
    assert parse_frontmatter("# Just a doc\n") == {}
    assert parse_frontmatter("---\nnever closed\n") == {}

"""Tests for pkgfence lookup query parsing."""
from scripts.lookup_parser import parse_query


def test_cve_normalized_uppercase():
    assert parse_query("cve-2019-10744") == {
        "type": "cve", "value": "CVE-2019-10744",
    }


def test_ghsa_keeps_canonical_lowercase_suffix():
    """GitHub Advisory IDs are GHSA- + lowercase alphanumeric groups.

    Uppercasing the whole ID diverges from osv-scanner / advisory permalinks
    and splits the on-disk GHSA cache key space.
    """
    assert parse_query("GHSA-jf85-cpcp-j695") == {
        "type": "ghsa", "value": "GHSA-jf85-cpcp-j695",
    }
    assert parse_query("ghsa-JF85-CPCP-J695") == {
        "type": "ghsa", "value": "GHSA-jf85-cpcp-j695",
    }


def test_mal_normalized_uppercase():
    assert parse_query("mal-2023-462") == {
        "type": "mal", "value": "MAL-2023-462",
    }


def test_purl_and_package_forms():
    assert parse_query("pkg:npm/express@4.18.2")["type"] == "purl"
    pkg = parse_query("npm:lodash@4.17.10")
    assert pkg["type"] == "package"
    assert pkg["ecosystem"] == "npm"
    assert pkg["name"] == "lodash"
    assert pkg["version"] == "4.17.10"


def test_free_text_fallback():
    assert parse_query("shai-hulud worm") == {
        "type": "free_text", "value": "shai-hulud worm",
    }

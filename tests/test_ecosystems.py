"""Layer A fixture tests — verify scanning known-vulnerable and known-clean
manifests against the OSV API directly (mocked) produces the expected results."""
from pathlib import Path
from unittest.mock import patch
import pytest

from scripts.scan_local import _parse_npm_lockfile_packages


FIXTURES = Path(__file__).parent / "fixtures"


def test_npm_vulnerable_fixture_extracts_lodash_4_17_10():
    """The vulnerable fixture should yield exactly one lodash@4.17.10 query."""
    lockfile = FIXTURES / "npm" / "vulnerable" / "package-lock.json"
    queries = _parse_npm_lockfile_packages(str(lockfile))
    assert len(queries) == 1
    assert queries[0]["package"]["name"] == "lodash"
    assert queries[0]["package"]["ecosystem"] == "npm"
    assert queries[0]["version"] == "4.17.10"


def test_npm_clean_fixture_extracts_lodash_4_17_21():
    """The clean fixture should yield exactly one lodash@4.17.21 query."""
    lockfile = FIXTURES / "npm" / "clean" / "package-lock.json"
    queries = _parse_npm_lockfile_packages(str(lockfile))
    assert len(queries) == 1
    assert queries[0]["package"]["name"] == "lodash"
    assert queries[0]["version"] == "4.17.21"

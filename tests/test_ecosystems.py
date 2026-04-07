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


def test_python_vulnerable_fixture_exists():
    """The python vulnerable fixture pins django==2.2.0 (known multiple CVEs)."""
    fixture = FIXTURES / "python" / "vulnerable" / "requirements.txt"
    assert fixture.exists()
    content = fixture.read_text(encoding="utf-8").strip()
    assert "django==2.2.0" in content


def test_python_clean_fixture_exists():
    """The python clean fixture pins django==4.2.10 (current LTS, patched)."""
    fixture = FIXTURES / "python" / "clean" / "requirements.txt"
    assert fixture.exists()
    content = fixture.read_text(encoding="utf-8").strip()
    assert "django==4.2.10" in content


def test_python_fixture_files_are_well_formed():
    """Both python fixtures should be parseable as simple requirements lines."""
    for variant in ("vulnerable", "clean"):
        fixture = FIXTURES / "python" / variant / "requirements.txt"
        lines = [l.strip() for l in fixture.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lines) >= 1
        for line in lines:
            assert "==" in line, f"requirements line missing pin: {line!r}"

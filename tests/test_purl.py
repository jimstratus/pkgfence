"""Tests for PURL (Package URL) canonical builder.
Round 2 finding R2-5: scoped npm packages need %40 percent-encoding."""
from scripts.lib.purl import build_purl, PurlError


def test_simple_npm_purl():
    assert build_purl("npm", "lodash", "4.17.20") == "pkg:npm/lodash@4.17.20"


def test_scoped_npm_purl_uses_percent_encoding():
    """The @ in @ctrl/tinycolor must become %40 per PURL spec."""
    assert build_purl("npm", "@ctrl/tinycolor", "4.0.7") == "pkg:npm/%40ctrl/tinycolor@4.0.7"


def test_python_purl():
    assert build_purl("pypi", "django", "4.2.0") == "pkg:pypi/django@4.2.0"


def test_cargo_purl():
    assert build_purl("cargo", "serde", "1.0.0") == "pkg:cargo/serde@1.0.0"


def test_maven_purl_requires_group():
    assert build_purl("maven", "org.springframework:spring-core", "5.3.0") == \
        "pkg:maven/org.springframework/spring-core@5.3.0"


def test_unknown_ecosystem_raises():
    import pytest
    with pytest.raises(PurlError):
        build_purl("frobnicator", "foo", "1.0")

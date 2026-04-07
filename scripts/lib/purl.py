"""Canonical Package URL (PURL) builder.

PURL spec: https://github.com/package-url/purl-spec

Round 2 finding R2-5: npm scoped packages (@scope/name) MUST encode the @
as %40 per the PURL spec. String concatenation produces wrong dedup keys.
"""
from urllib.parse import quote


class PurlError(ValueError):
    pass


_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "pypi",
    "python": "pypi",
    "pip": "pypi",
    "cargo": "cargo",
    "rust": "cargo",
    "maven": "maven",
    "java": "maven",
    "gem": "gem",
    "rubygems": "gem",
    "ruby": "gem",
    "composer": "composer",
    "php": "composer",
    "golang": "golang",
    "go": "golang",
    "nuget": "nuget",
    "dotnet": "nuget",
}


def build_purl(ecosystem: str, name: str, version: str) -> str:
    """Build a canonical PURL string for (ecosystem, name, version).

    Args:
        ecosystem: e.g., 'npm', 'pypi', 'cargo', 'maven'. See _ECOSYSTEM_MAP.
        name: Package name. For npm scoped packages, include the leading @.
              For Maven, use 'group:artifact' notation.
        version: Version string.

    Returns:
        Canonical PURL string, e.g. 'pkg:npm/%40scope/name@1.0.0'.

    Raises:
        PurlError: if ecosystem is unknown or name is empty.
    """
    if not name:
        raise PurlError("Package name is required")
    eco = _ECOSYSTEM_MAP.get(ecosystem.lower())
    if eco is None:
        raise PurlError(f"Unknown ecosystem: {ecosystem!r}")
    if eco == "maven":
        if ":" not in name:
            raise PurlError(f"Maven name must be 'group:artifact', got {name!r}")
        group, artifact = name.split(":", 1)
        return f"pkg:maven/{quote(group, safe='')}/{quote(artifact, safe='')}@{version}"
    # For npm scoped packages, percent-encode the @ in the scope
    encoded_name = quote(name, safe="/")
    return f"pkg:{eco}/{encoded_name}@{version}"

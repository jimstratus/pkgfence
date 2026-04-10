"""Layer: Is-installed check for local findings.

Determines whether a package referenced in a lockfile is actually installed
on disk. This reduces false-positive CRITICAL fatigue — a finding for a
package that isn't installed on disk is lower-risk.

Supported ecosystems:
    npm      — checks node_modules/<name>/ adjacent to package-lock.json
    composer — checks vendor/<vendor>/<package>/ adjacent to composer.lock
    pip      — skipped (virtualenv ambiguity makes this unreliable)
"""
from pathlib import Path
from urllib.parse import unquote

from scripts.lib.types import Finding


def _extract_package_name(purl: str) -> str:
    """Extract the package name from a PURL string.

    Examples:
        pkg:npm/lodash@4.17.21        -> lodash
        pkg:npm/%40babel/core@7.0     -> @babel/core
        pkg:composer/monolog/monolog@2.0 -> monolog/monolog
    """
    # Strip scheme prefix: "pkg:npm/..." -> "npm/..."
    if ":" in purl:
        purl = purl.split(":", 1)[1]

    # Strip ecosystem prefix: "npm/lodash@4.17.21" -> "lodash@4.17.21"
    if "/" in purl:
        _, rest = purl.split("/", 1)
    else:
        rest = purl

    # Strip version suffix: "lodash@4.17.21" -> "lodash"
    if "@" in rest:
        name = rest.rsplit("@", 1)[0]
    else:
        name = rest

    # URL-decode: %40babel/core -> @babel/core
    return unquote(name)


def _lockfile_name(manifest_path: str) -> str:
    """Return the filename portion of manifest_path (lowercase)."""
    return Path(manifest_path).name.lower()


def check_installed_local(finding: Finding) -> Finding:
    """Check whether the package in *finding* is installed on disk.

    Sets finding["installed"] = True/False for npm and composer findings.
    Returns the finding unchanged for unsupported ecosystems (pip, etc.).
    """
    manifest_path = finding.get("manifest_path", "")
    lockfile = _lockfile_name(manifest_path)
    lockfile_dir = Path(manifest_path).parent

    if lockfile == "package-lock.json":
        pkg_name = _extract_package_name(finding.get("purl", ""))
        install_path = lockfile_dir / "node_modules" / pkg_name
        finding["installed"] = install_path.exists()
        return finding

    if lockfile == "composer.lock":
        pkg_name = _extract_package_name(finding.get("purl", ""))
        # composer names are "vendor/package" — split into two path components
        parts = pkg_name.split("/", 1)
        if len(parts) == 2:
            install_path = lockfile_dir / "vendor" / parts[0] / parts[1]
        else:
            install_path = lockfile_dir / "vendor" / pkg_name
        finding["installed"] = install_path.exists()
        return finding

    # Unsupported ecosystem (pip, cargo, etc.) — leave finding unchanged
    return finding

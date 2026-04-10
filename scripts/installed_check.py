"""Layer: Is-installed check for local and remote findings.

Determines whether a package referenced in a lockfile is actually installed
on disk. This reduces false-positive CRITICAL fatigue — a finding for a
package that isn't installed on disk is lower-risk.

Supported ecosystems:
    npm      — checks node_modules/<name>/ adjacent to package-lock.json
    composer — checks vendor/<vendor>/<package>/ adjacent to composer.lock
    pip      — skipped (virtualenv ambiguity makes this unreliable)
"""
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError
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


_DEMOTABLE_SEVERITIES = {"critical", "high"}


def apply_installed_demotion(finding: Finding) -> Finding:
    """Demote severity to info if finding's package is not installed.
    Only demotes critical and high. Preserves original_severity."""
    if finding.get("installed") is False and finding.get("severity") in _DEMOTABLE_SEVERITIES:
        finding["original_severity"] = finding["severity"]
        finding["severity"] = "info"
    return finding


def apply_installed_checks_local(
    findings: list[Finding],
    local_manifest_paths: set[str] | None = None,
) -> list[Finding]:
    """Run is-installed check + demotion on local findings.

    If *local_manifest_paths* is provided, only findings whose manifest_path
    is in that set are checked (skips remote SSH findings that share the same
    pipeline but have paths on a different machine).
    """
    for f in findings:
        if f.get("status") == "SCAN_ERROR":
            continue
        if local_manifest_paths is not None and f.get("manifest_path") not in local_manifest_paths:
            continue
        check_installed_local(f)
        apply_installed_demotion(f)
    return findings


def check_installed_remote(finding: Finding, runner: SSHRunner) -> Finding:
    """Check whether the package in *finding* is installed on the remote host.

    Uses ``runner.run_with_rc(["stat", install_path])`` — rc=0 means installed,
    rc≠0 means not installed.

    On SSHUnreachableError: returns the finding unchanged (unknown state,
    do not demote). For unsupported ecosystems (pip, etc.): returns unchanged.

    Uses PurePosixPath for remote paths (safe on Windows hosts too).
    """
    manifest_path = finding.get("manifest_path", "")
    lockfile = _lockfile_name(manifest_path)
    manifest_dir = PurePosixPath(manifest_path).parent

    if lockfile == "package-lock.json":
        pkg_name = _extract_package_name(finding.get("purl", ""))
        install_path = str(manifest_dir / "node_modules" / pkg_name)
    elif lockfile == "composer.lock":
        pkg_name = _extract_package_name(finding.get("purl", ""))
        parts = pkg_name.split("/", 1)
        if len(parts) == 2:
            install_path = str(manifest_dir / "vendor" / parts[0] / parts[1])
        else:
            install_path = str(manifest_dir / "vendor" / pkg_name)
    else:
        # Unsupported ecosystem (pip, cargo, etc.) — leave finding unchanged
        return finding

    try:
        _stdout, rc = runner.run_with_rc(["stat", install_path])
        finding["installed"] = rc == 0
    except SSHUnreachableError:
        pass  # Unknown state — do not set installed field

    return finding

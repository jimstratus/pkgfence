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
from scripts.lib.types import Finding, is_status_record


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


def _install_path_for(finding: Finding) -> str | None:
    """POSIX install-dir for the finding's package, anchored at the
    manifest's directory; None for unsupported ecosystems (pip etc.)."""
    manifest_path = finding.get("manifest_path", "")
    lockfile = _lockfile_name(manifest_path)
    manifest_dir = PurePosixPath(manifest_path).parent
    pkg_name = _extract_package_name(finding.get("purl", ""))
    if lockfile == "package-lock.json":
        return str(manifest_dir / "node_modules" / pkg_name)
    if lockfile == "composer.lock":
        parts = pkg_name.split("/", 1)
        if len(parts) == 2:
            return str(manifest_dir / "vendor" / parts[0] / parts[1])
        return str(manifest_dir / "vendor" / pkg_name)
    return None


def check_installed_remote_batch(
    findings: list[Finding], runner: SSHRunner
) -> list[Finding]:
    """Set finding['installed'] for a batch of same-target findings using
    ONE `ls -d path1 path2 ...` round-trip (issue #19.1) instead of one
    stat session per finding. `ls -d` prints existing paths to stdout and
    errors for missing ones — rc is ignored, stdout is the answer.

    On SSHUnreachableError: findings stay unchanged (unknown state, never
    demote on no-evidence)."""
    by_path: list[tuple[Finding, str]] = []
    for f in findings:
        install_path = _install_path_for(f)
        if install_path:
            by_path.append((f, install_path))
    unique_paths = sorted({p for _, p in by_path})
    if not unique_paths:
        return findings
    CHUNK = 100  # bound remote argv length (same bound as discovery hashing)
    existing: set[str] = set()
    try:
        for i in range(0, len(unique_paths), CHUNK):
            stdout, _rc = runner.run_with_rc(
                ["ls", "-d"] + unique_paths[i:i + CHUNK])
            existing.update(
                line.strip() for line in stdout.splitlines() if line.strip())
    except SSHUnreachableError:
        return findings
    for f, p in by_path:
        f["installed"] = p in existing
    return findings


def apply_installed_checks(
    findings: list[Finding],
    local_manifest_paths: set[str],
    remote_runners: dict[str, SSHRunner],
) -> list[Finding]:
    """Single installed-check stage for local AND remote findings
    (issue #20.2 — previously remote ran at L2b and local at L4, producing
    divergent outcomes for identical findings). Local findings are checked
    via Path.exists, remote via one batched ls -d per target; demotion then
    applies identically to both."""
    remote_by_target: dict[str, list[Finding]] = {}
    for f in findings:
        if is_status_record(f):
            continue
        if f.get("manifest_path") in local_manifest_paths:
            check_installed_local(f)
        elif f.get("target") in remote_runners:
            remote_by_target.setdefault(f["target"], []).append(f)
    for target, target_findings in remote_by_target.items():
        check_installed_remote_batch(target_findings, remote_runners[target])
    for f in findings:
        if not is_status_record(f):
            apply_installed_demotion(f)
    return findings

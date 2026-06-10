"""EOL software detection via curated catalog.

Performs its own filesystem walk (separate from L1 manifest discovery) to
detect end-of-life software installations. Walks vendor/ directories too —
do NOT add DEFAULT_EXCLUDES here.
"""
import logging
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any

from scripts.lib.config import load_yaml
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError
from scripts.lib.types import Finding, new_finding

log = logging.getLogger(__name__)

SKILL_ROOT = Path(__file__).parent.parent
EOL_CATALOG_PATH = SKILL_ROOT / "config" / "eol-catalog.yaml"


def load_eol_catalog() -> list[dict[str, Any]]:
    """Load the EOL software catalog from config/eol-catalog.yaml.

    The catalog is read-only (never round-tripped back to disk), so the
    shared safe loader is the single source of truth (issue #18.4)."""
    return list(load_yaml(EOL_CATALOG_PATH) or [])


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Split version string on '.' and return tuple of ints for comparison."""
    parts = []
    for part in version_str.strip().split("."):
        # Strip any non-numeric suffix (e.g. "1alpha" -> 1)
        match = re.match(r"(\d+)", part)
        parts.append(int(match.group(1)) if match else 0)
    return tuple(parts)


def _is_eol(detected_version: str, eol_before: str) -> bool:
    """Return True if detected_version < eol_before."""
    return _parse_version(detected_version) < _parse_version(eol_before)


def _read_version(base_dir: str, entry: dict[str, Any]) -> str | None:
    """Read and return the version string for a detected installation."""
    version_file = entry.get("version_file")
    if not version_file:
        return None

    version_path = Path(base_dir) / version_file
    if not version_path.is_file():
        return None

    try:
        content = version_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    version_regex = entry.get("version_regex")
    if version_regex:
        match = re.search(version_regex, content)
        if match:
            return match.group(1).strip()
        return None
    else:
        # Plain version file — entire content is the version
        return content.strip() or None


def detect_eol_local(root_paths: list[str]) -> list[Finding]:
    """Walk root_paths and detect EOL software installations.

    Args:
        root_paths: List of filesystem roots to walk.

    Returns:
        List of Finding dicts for any EOL installations detected.
    """
    catalog = load_eol_catalog()
    findings: list[Finding] = []

    for root in root_paths:
        for dirpath, dirnames, filenames in os.walk(root):
            filename_set = set(filenames)
            dirname_set = set(dirnames)
            for entry in catalog:
                detect = entry.get("detect", {})
                detect_file = detect.get("file", "")
                path_contains = detect.get("path_contains")

                # Cheap pre-filter from the walk's own listing (issue #19.4:
                # blind is_file() per dir×entry ≈ millions of stats on a
                # large tree). Single-component detect files must appear in
                # filenames; multi-component ones need their first directory
                # component present in dirnames.
                parts = Path(detect_file).parts if detect_file else ()
                if not parts:
                    continue
                if len(parts) == 1:
                    if parts[0] not in filename_set:
                        continue
                elif parts[0] not in dirname_set:
                    continue

                fingerprint_path = Path(dirpath) / detect_file
                if not fingerprint_path.is_file():
                    continue

                # Optional: path must contain a substring
                if path_contains and path_contains.lower() not in dirpath.lower():
                    continue

                install_root = dirpath

                version = _read_version(install_root, entry)
                if version is None:
                    continue

                eol_before = entry.get("eol_before")
                if eol_before is None:
                    # Defer to API — no local EOL judgment
                    continue

                if not _is_eol(version, eol_before):
                    continue

                name = entry["name"]
                finding = new_finding(
                    purl=f"pkg:generic/{name}@{version}",
                    vuln_id=f"EOL-{name}-{version}",
                    severity="high",
                    manifest_path=str(fingerprint_path),
                    installed=True,
                )
                findings.append(finding)

    return findings


def _build_eol_find_command(
    discover_paths: list[str], catalog: list[dict[str, Any]]
) -> list[str]:
    """Build a `find` argv matching all catalog detect.file patterns."""
    cmd = ["find"] + list(discover_paths)
    cmd += ["-maxdepth", "6"]
    cmd += ["("]
    first = True
    for entry in catalog:
        detect_file = entry.get("detect", {}).get("file", "")
        if not detect_file:
            continue
        # detect.file may be a relative path like "wp-includes/version.php";
        # extract just the filename for the -name filter.
        filename = detect_file.rsplit("/", 1)[-1]
        if not first:
            cmd += ["-o"]
        cmd += ["-name", filename]
        first = False
    cmd += [")", "-print"]
    return cmd


# A version string is a short token like "9.0.0" / "6.4.2-alpha1" — never a
# multi-line blob. Caps the S4a exfil channel: at most one version-shaped
# token can transit, not arbitrary file contents.
_VERSION_RE = re.compile(r"[0-9A-Za-z._+~-]{1,64}")


def _is_safe_remote_version_path(version_path: str, discover_paths: list[str]) -> bool:
    """True only if version_path is absolute, has no traversal segments,
    and sits under one of the configured discover_paths. find-derived
    directories are remote-controlled input — never cat outside the roots
    we were told to scan (issue #8)."""
    p = PurePosixPath(version_path)
    if not p.is_absolute():
        return False
    if ".." in p.parts:  # pathlib strips "." segments; ".." survives
        return False
    return any(p.is_relative_to(PurePosixPath(root)) for root in discover_paths)


def detect_eol_remote(
    discover_paths: list[str],
    runner: SSHRunner,
    target_name: str,
    target_host: str,
) -> list[Finding]:
    """Detect EOL software on a remote host via SSH find + cat.

    Builds a find command from the EOL catalog's detect.file patterns, then
    reads each matched installation's version_file via `cat`. Version strings
    are compared against eol_before to emit Findings.

    S4 scoped exception (S4a): cat reads version files whose directory comes
    from remote `find` output. That path is therefore remote-controlled, so it
    is validated to stay under discover_paths, and the extracted version must
    match a strict version-token pattern before it is used. Residual risk: the
    containment is lexical — a symlink under discover_paths can still point
    elsewhere — but the version-token cap bounds what can transit to one short
    token, not file contents. See issue #8.

    Args:
        discover_paths: Remote paths to search (e.g. ["/var/www"]).
        runner: SSHRunner bound to the target host.
        target_name: Human-readable target name (used in Finding.target).
        target_host: Target hostname or IP (informational).

    Returns:
        List of Finding dicts for any EOL installations detected.
    """
    catalog = load_eol_catalog()
    findings: list[Finding] = []

    find_cmd = _build_eol_find_command(discover_paths, catalog)

    try:
        find_output = runner.run(find_cmd)
    except SSHUnreachableError as e:
        log.warning("EOL remote scan: SSH unreachable for %s (%s): %s",
                    target_name, target_host, e)
        return []

    matched_paths = [line.strip() for line in find_output.splitlines() if line.strip()]
    if not matched_paths:
        return []

    for matched_path in matched_paths:
        # Determine which catalog entry this file belongs to.
        matched_filename = matched_path.rsplit("/", 1)[-1]
        matched_dir = matched_path.rsplit("/", 1)[0] if "/" in matched_path else ""

        for entry in catalog:
            detect = entry.get("detect", {})
            detect_file = detect.get("file", "")
            if not detect_file:
                continue

            entry_filename = detect_file.rsplit("/", 1)[-1]
            if entry_filename != matched_filename:
                continue

            # Optional path_contains filter
            path_contains = detect.get("path_contains")
            if path_contains and path_contains.lower() not in matched_path.lower():
                continue

            # Resolve the installation root: strip the detect_file subdirectory
            # prefix from matched_dir if detect_file has subdirectory components.
            detect_file_parts = detect_file.rsplit("/", 1)
            if len(detect_file_parts) > 1:
                # detect_file is like "wp-includes/version.php" — the install
                # root is matched_dir minus the leading subdir component.
                subdir = detect_file_parts[0]
                if matched_dir.endswith("/" + subdir):
                    install_root = matched_dir[: -(len(subdir) + 1)]
                else:
                    install_root = matched_dir
            else:
                install_root = matched_dir

            version_file = entry.get("version_file")
            if not version_file:
                continue

            version_path = install_root.rstrip("/") + "/" + version_file

            if not _is_safe_remote_version_path(version_path, discover_paths):
                # %r on the remote-controlled path so log-escape control
                # chars can't forge terminal/log output (review follow-up).
                log.warning(
                    "EOL remote scan: refusing to read %r on %s (outside discover_paths)",
                    version_path, target_name,
                )
                continue

            try:
                cat_output = runner.run(["cat", version_path])
            except SSHUnreachableError as e:
                log.warning("EOL remote scan: SSH lost while reading %s on %s: %s",
                            version_path, target_name, e)
                return findings

            if not cat_output or not cat_output.strip():
                continue  # missing or empty version file — skip silently

            version_regex = entry.get("version_regex")
            if version_regex:
                m = re.search(version_regex, cat_output)
                if not m:
                    log.warning(
                        "EOL remote scan: %s on %s did not match version_regex "
                        "for %s; skipping", version_path, target_name, entry["name"],
                    )
                    continue
                version = m.group(1).strip()
            else:
                # Plain version file — take only the FIRST line, and only
                # if it looks like a version token (S4a containment).
                first_line = cat_output.strip().splitlines()[0].strip()
                version = first_line
            # Must be a version-shaped token AND contain a digit — a digit-free
            # token ("---") parses to (0,) and would forge a noise EOL finding.
            if (not version or not _VERSION_RE.fullmatch(version)
                    or not any(c.isdigit() for c in version)):
                log.warning(
                    "EOL remote scan: %s on %s (%s) did not yield a version-shaped "
                    "string; skipping", version_path, target_name, entry["name"],
                )
                continue

            eol_before = entry.get("eol_before")
            if eol_before is None:
                continue  # defer to API — no local EOL judgment

            if not _is_eol(version, eol_before):
                continue

            name = entry["name"]
            finding = new_finding(
                purl=f"pkg:generic/{name}@{version}",
                vuln_id=f"EOL-{name}-{version}",
                severity="high",
                manifest_path=matched_path,
                installed=True,
            )
            finding["target"] = target_name
            finding["host"] = target_host
            findings.append(finding)
            break  # matched one catalog entry for this path; move on

    return findings

"""EOL software detection via curated catalog.

Performs its own filesystem walk (separate from L1 manifest discovery) to
detect end-of-life software installations. Walks vendor/ directories too —
do NOT add DEFAULT_EXCLUDES here.
"""
import logging
import os
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError
from scripts.lib.types import Finding, new_finding

log = logging.getLogger(__name__)

SKILL_ROOT = Path(__file__).parent.parent
EOL_CATALOG_PATH = SKILL_ROOT / "config" / "eol-catalog.yaml"

_yaml = YAML(typ="rt")


def load_eol_catalog() -> list[dict[str, Any]]:
    """Load the EOL software catalog from config/eol-catalog.yaml."""
    data = _yaml.load(EOL_CATALOG_PATH.read_text(encoding="utf-8"))
    return list(data)


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
            for entry in catalog:
                detect = entry.get("detect", {})
                detect_file = detect.get("file", "")
                path_contains = detect.get("path_contains")

                # Check if the fingerprint file exists in this directory
                # For entries like "wp-includes/version.php", the detect.file
                # is a relative path — we check if the full relative path exists
                # anchored at dirpath.
                fingerprint_path = Path(dirpath) / detect_file
                if not fingerprint_path.is_file():
                    continue

                # Optional: path must contain a substring
                if path_contains and path_contains.lower() not in dirpath.lower():
                    continue

                # Determine the installation root: strip the detect_file subpath
                # from dirpath so that version_file is resolved relative to root.
                # e.g. detect.file = "wp-includes/version.php", dirpath = "/var/www"
                # -> installation root = /var/www (dirpath itself, not a subdir)
                detect_file_parts = Path(detect_file).parts
                if len(detect_file_parts) > 1:
                    # The detect file is in a subdirectory — installation root is dirpath
                    install_root = dirpath
                else:
                    # The detect file is directly in the dir — installation root is dirpath
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
    cmd += ["\\("]
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
    cmd += ["\\)", "-print"]
    return cmd


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

    S4 scoped exception: cat is used to read version files derived solely from
    catalog-defined version_file patterns — never from user input or discovery
    output. Task 10 adds the safety test for this boundary.

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
                    continue  # malformed — skip silently
                version = m.group(1).strip()
            else:
                version = cat_output.strip()

            if not version:
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

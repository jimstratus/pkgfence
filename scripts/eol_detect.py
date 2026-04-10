"""EOL software detection via curated catalog.

Performs its own filesystem walk (separate from L1 manifest discovery) to
detect end-of-life software installations. Walks vendor/ directories too —
do NOT add DEFAULT_EXCLUDES here.
"""
import os
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from scripts.lib.types import Finding, new_finding

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

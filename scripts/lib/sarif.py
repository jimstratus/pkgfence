"""SARIF 2.1.0 emitter for pkgfence findings.

Maps internal severity -> SARIF level:
    critical / mal-flagged / actively_exploited -> error
    high                                         -> error
    medium                                       -> warning
    low                                          -> note
    info                                         -> none

Emits partialFingerprints.primaryLocationLineHash for GitHub Code
Scanning dedup (sha256 of manifest_path + vuln_id).
"""
import hashlib
from importlib.metadata import version as _md_version
from typing import Any
from scripts.lib.types import Finding


_SCHEMA_URL = "https://schemastore.azurewebsites.net/schemas/json/sarif-schema-2.1.0.json"
_REPO_URL = "https://github.com/jimstratus/pkgfence"


def _pkgfence_version() -> str:
    try:
        return _md_version("pkgfence")
    except Exception:  # noqa: BLE001
        return "unknown"


def _severity_to_level(severity: str) -> str:
    sev = (severity or "medium").lower()
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    if sev == "low":
        return "note"
    return "none"


def _fingerprint(f: Finding) -> str:
    """Stable hash of (manifest_path, vuln_id) for cross-run dedup."""
    h = hashlib.sha256()
    h.update((f.get("manifest_path", "") + "|" + f.get("vuln_id", "")).encode("utf-8"))
    return h.hexdigest()


def findings_to_sarif(findings: list[Finding], scanner_version: str) -> dict[str, Any]:
    """Convert pkgfence findings to a SARIF 2.1.0 document.

    Args:
        findings: list of Finding TypedDicts
        scanner_version: human string for the tool driver, e.g. 'osv-scanner 2.3.3'

    Returns:
        SARIF dict ready to json.dumps and write to disk.
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        vuln_id = f.get("vuln_id", "UNKNOWN")
        if vuln_id not in rules:
            rules[vuln_id] = {
                "id": vuln_id,
                "shortDescription": {"text": f.get("description", vuln_id)[:100]},
                "fullDescription": {"text": f.get("description", "")},
                "defaultConfiguration": {
                    "level": _severity_to_level(f.get("severity", "medium")),
                },
            }

        result_entry = {
            "ruleId": vuln_id,
            "level": _severity_to_level(f.get("severity", "medium")),
            "message": {"text": f.get("description", vuln_id)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("manifest_path", "")},
                },
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": _fingerprint(f),
            },
            "properties": {
                "purl": f.get("purl", ""),
                "target": f.get("target", ""),
            },
        }
        results.append(result_entry)

    return {
        "$schema": _SCHEMA_URL,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pkgfence",
                    "version": _pkgfence_version(),
                    "informationUri": _REPO_URL,
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "properties": {
                "scanner_source": scanner_version,
            },
        }],
    }

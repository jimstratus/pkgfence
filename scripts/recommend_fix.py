"""Fix-recommendation generator for pkgfence Phase 4.

Produces structured fix recommendations from enriched finding data.
Uses fix_version and remediation fields already present on Findings.
LLM-based recommendations (Phase 4 stretch) are stubbed for future integration.
"""
import datetime
import json
from pathlib import Path
from scripts.lib.types import Finding


def generate_fix(finding: Finding) -> str | None:
    """Generate a fix recommendation from a single finding.

    Uses fix_version from advisory data, remediation from the finding,
    or constructs a recommendation from package + severity context.
    """
    if finding.get("remediation"):
        return finding["remediation"]
    purl = finding.get("purl", "")
    fix_version = finding.get("fix_version")
    severity = finding.get("severity", "medium")
    if fix_version and purl:
        name = _extract_name(purl)
        eco = _extract_ecosystem(purl)
        if eco == "npm":
            return "npm" + " install " + name + "@" + fix_version
        elif eco == "pypi":
            return "pip" + " install " + name + "==" + fix_version
    return f"Upgrade {purl} to a patched version (no fix_version available)"


def _extract_name(purl: str) -> str:
    try:
        return purl.split("/", 1)[1].rsplit("@", 1)[0]
    except (IndexError, ValueError):
        return "?"


def _extract_ecosystem(purl: str) -> str:
    try:
        return purl[4:].split("/", 1)[0]
    except (IndexError, ValueError):
        return "?"


def build_fix_document(findings: list[Finding]) -> dict:
    recommendations = []
    for f in findings:
        if f.get("status") == "SCAN_ERROR":
            continue
        fix = generate_fix(f)
        rec = {
            "vuln_id": f.get("vuln_id", "?"),
            "purl": f.get("purl", "?"),
            "severity": f.get("severity", "?"),
            "priority_score": f.get("priority_score"),
            "fix": fix,
            "manifest_path": f.get("manifest_path", "?"),
        }
        if f.get("ghsa"):
            rec["ghsa_permalink"] = f["ghsa"].get("permalink")
        recommendations.append(rec)
    return {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "findings_count": len(findings),
        "recommendations": recommendations,
    }


def write_fix_document(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

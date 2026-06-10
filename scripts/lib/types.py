"""Shared type definitions for pkgfence.

Using TypedDict instead of dataclass because findings flow through
subprocess JSON, file I/O, and test fixtures — plain dicts roundtrip
trivially while dataclasses would need serializers.
"""
from typing import TypedDict, Literal, Any


Severity = Literal["critical", "high", "medium", "low", "info"]
DiffStatus = Literal["NEW", "CHANGED", "EXISTING"]
Status = Literal["OK", "SCAN_ERROR", "WAIVED"]

# Single source of truth for severity ordering (issue #18). The --fail-on
# gate, notify thresholds, and triage sort all rank through this dict.
SEVERITY_RANK: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}


class Finding(TypedDict, total=False):
    """A single vulnerability finding, normalized across scanners.

    Fields marked required by convention but typed total=False so we can
    construct incrementally through the pipeline.

    Required at output time:
        purl            — canonical PURL (see scripts/lib/purl.py)
        vuln_id         — primary advisory ID (GHSA-*, CVE-*, MAL-*)
        severity        — critical | high | medium | low | info
        manifest_path   — absolute path to the manifest that introduced the dep
        target          — the registry target name (local root / project / SSH host)

    Set during enrichment / triage:
        aliases             — list of other advisory IDs (checked for MAL-* too)
        description         — human-readable summary
        fix_version         — the patched version to upgrade to
        actively_exploited  — bool, true if cveID appears in CISA KEV
        epss_score          — float [0, 1], probability of exploitation
        epss_percentile     — float [0, 1], percentile rank in EPSS
        cvss_score          — raw CVSS base score from osv-scanner output
        priority_score      — 0.0-1.0 triple-score (CVSS + EPSS + KEV)
        kev_date_added      — ISO date when KEV added the CVE
        direct              — bool, true if this is a direct dep (not transitive)
        diff_status         — NEW | CHANGED | EXISTING (from baseline comparison)
        status              — OK | SCAN_ERROR | WAIVED
        mal_flagged         — bool, true if id or aliases contain MAL-* prefix
        remediation         — copy-pasteable command to fix
        scanner_source      — 'osv-scanner' | 'osv-api' | etc. (for conflict resolution)
        installed           — True/False whether the package is installed (absent = not applicable)
        original_severity   — severity before demotion (set only when severity demotion occurs)
    """
    purl: str
    vuln_id: str
    severity: Severity
    manifest_path: str
    target: str
    aliases: list[str]
    description: str
    fix_version: str
    actively_exploited: bool
    epss_score: float
    epss_percentile: float
    cvss_score: float
    priority_score: float
    kev_date_added: str
    direct: bool
    diff_status: DiffStatus
    status: Status
    mal_flagged: bool
    remediation: str
    scanner_source: str
    installed: bool
    original_severity: Severity


def new_finding(
    purl: str,
    vuln_id: str,
    severity: Severity,
    manifest_path: str,
    target: str = "",
    **extras: Any,
) -> Finding:
    """Construct a Finding with sensible defaults for the optional fields."""
    f: Finding = {
        "purl": purl,
        "vuln_id": vuln_id,
        "severity": severity,
        "manifest_path": manifest_path,
        "target": target,
        "aliases": [],
        "actively_exploited": False,
        "diff_status": "NEW",
        "status": "OK",
        "mal_flagged": False,
    }
    f.update(extras)
    return f


def is_status_record(finding: Finding) -> bool:
    """True for pipeline-status records (SCAN_ERROR) rather than actual
    vulnerabilities. Status records flow through every stage UNCHANGED:
    never deduped, enriched, scored, demoted, or excluded (issue #10)."""
    return finding.get("status") == "SCAN_ERROR"

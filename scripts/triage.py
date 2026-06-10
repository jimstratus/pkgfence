"""Layer 4: Triage — dedup, scoring, sorting, filtering.

Phase 1 scope (this file is built up across Tasks 10.1-10.5):
- 10.1: basic dedup by (purl, vuln_id)
- 10.2: MAL-* override (checks id AND aliases[])
- 10.3: expiring exceptions
- 10.4: deterministic sort
- 10.5: hardcoded exclusions list
"""
from scripts.lib.types import Finding, is_status_record


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by (purl, vuln_id) tuple. First occurrence wins."""
    seen: set[tuple[str, str]] = set()
    result: list[Finding] = []
    for f in findings:
        if is_status_record(f):
            result.append(f)  # status records are never deduped (issue #10)
            continue
        key = (f.get("purl", ""), f.get("vuln_id", ""))
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
    return result


def apply_mal_override(findings: list[Finding]) -> list[Finding]:
    """Round 2 finding R2-9: MAL-* prefix indicates a malicious package
    record from OpenSSF Malicious Packages. Bypass severity triage and
    override to critical regardless of CVSS.

    Critic gap fix: check BOTH the primary id field AND the aliases[]
    array. Many findings have a primary GHSA id with the MAL-* in aliases.
    """
    for f in findings:
        primary = f.get("vuln_id", "")
        aliases = f.get("aliases", [])
        all_ids = [primary] + list(aliases)
        if any(vid.startswith("MAL-") for vid in all_ids if vid):
            f["severity"] = "critical"
            f["mal_flagged"] = True
            f["remediation"] = (
                "Remove this package immediately — it is flagged as "
                "malicious by OpenSSF Malicious Packages."
            )
    return findings


import datetime as _datetime
from scripts.lib.exceptions import is_exception_active


def apply_exceptions(
    findings: list[Finding],
    exceptions: list[dict],
    today: "_datetime.date | None" = None,
) -> list[Finding]:
    """Filter out findings matching any active exception.

    Match logic for MVP: exception matches a finding if:
    - vuln_id matches (exact string)
    - scope is empty OR finding.manifest_path starts with exception.scope

    Expired exceptions are ignored (finding survives).
    """
    if today is None:
        today = _datetime.date.today()
    active = [e for e in exceptions if is_exception_active(e, today)]
    if not active:
        return findings

    def is_suppressed(f: Finding) -> bool:
        for exc in active:
            if exc.get("vuln_id") != f.get("vuln_id"):
                continue
            scope = exc.get("scope", "")
            if not scope or f.get("manifest_path", "").startswith(scope):
                return True
        return False

    return [f for f in findings if not is_suppressed(f)]


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings deterministically: severity first (critical → info),
    then by priority_score descending within each severity bucket,
    then alphabetically by purl, then by vuln_id."""
    def key(f: Finding):
        return (
            SEVERITY_RANK.get(f.get("severity", "medium"), 99),
            -float(f.get("priority_score") or 0.0),  # negative for descending
            f.get("purl", ""),
            f.get("vuln_id", ""),
        )
    return sorted(findings, key=key)


def apply_exclusions(findings: list[Finding], config: dict) -> list[Finding]:
    """Filter out findings matching the exclusion config.

    Args:
        findings: list of Findings (post-dedup, post-MAL-override)
        config: dict with keys 'exclude_severities_below', 'exclude_categories'

    Rules:
    - SCAN_ERROR records always survive (they're status reports, not findings)
    - Findings with severity below floor are excluded
    - Findings whose description matches any excluded category are excluded
    """
    floor = config.get("exclude_severities_below", "info")
    floor_rank = SEVERITY_RANK.get(floor, 99)
    excluded_cats = set(config.get("exclude_categories", []))

    def keep(f: Finding) -> bool:
        if is_status_record(f):
            return True
        sev_rank = SEVERITY_RANK.get(f.get("severity", "medium"), 2)
        if sev_rank > floor_rank:
            return False
        desc_lower = f.get("description", "").lower()
        for cat in excluded_cats:
            if cat.replace("_", " ") in desc_lower:
                return False
        return True

    return [f for f in findings if keep(f)]

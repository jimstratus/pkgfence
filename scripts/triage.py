"""Layer 4: Triage — dedup, scoring, sorting, filtering.

Phase 1 scope (this file is built up across Tasks 10.1-10.5):
- 10.1: basic dedup by (purl, vuln_id)
- 10.2: MAL-* override (checks id AND aliases[])
- 10.3: expiring exceptions
- 10.4: deterministic sort
- 10.5: hardcoded exclusions list
"""
from scripts.lib.types import Finding


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by (purl, vuln_id) tuple. First occurrence wins."""
    seen: set[tuple[str, str]] = set()
    result: list[Finding] = []
    for f in findings:
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

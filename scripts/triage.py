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

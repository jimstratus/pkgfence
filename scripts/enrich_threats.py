"""Threat intel enrichment overlays.

Layer 3 of the pkgfence pipeline. Takes raw Finding records from Layer 2
(scanners) and adds enrichment fields:
- actively_exploited (bool) from CISA KEV
- (Phase 2+: epss_score, deps.dev health, GHSA cross-check)
"""
from scripts.lib.types import Finding, is_status_record
from scripts.lib.kev_client import KEVClient


def enrich_with_kev(findings: list[Finding], kev: KEVClient) -> list[Finding]:
    """Mark findings as actively_exploited if their vuln_id (or any alias)
    appears in CISA KEV.

    Round 2 finding: KEV joins via cveID only. Many scanner findings have
    a primary GHSA-* id with the corresponding CVE in aliases[]. We must
    check both.
    """
    for f in findings:
        if is_status_record(f):
            continue  # status records flow through unchanged (issue #10)
        all_ids = [f.get("vuln_id", "")] + list(f.get("aliases", []))
        f["actively_exploited"] = any(kev.is_known_exploited(vid) for vid in all_ids if vid)
    return findings

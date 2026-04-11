"""L3.5 EPSS enrichment — adds exploit-probability scores from FIRST.org.

For each finding with a CVE in vuln_id or aliases, look up the EPSS score
and percentile and attach them to the Finding.

SCAN_ERROR records are skipped (they're status reports, not findings).
Findings without a CVE (MAL-*, EOL-*, GHSA-only) are unchanged.
"""
from scripts.lib.types import Finding
from scripts.lib.epss_client import EPSSClient
from scripts.lib.logger import get_logger

log = get_logger(__name__)


def _find_cve_id(finding: Finding) -> str | None:
    """Return the first CVE-* ID in vuln_id or aliases, else None."""
    vid = finding.get("vuln_id", "")
    if vid.startswith("CVE-"):
        return vid
    for alias in finding.get("aliases", []):
        if isinstance(alias, str) and alias.startswith("CVE-"):
            return alias
    return None


def enrich_with_epss(
    findings: list[Finding], epss: EPSSClient
) -> list[Finding]:
    """Set epss_score and epss_percentile on findings with a CVE alias."""
    for f in findings:
        if f.get("status") == "SCAN_ERROR":
            continue
        cve = _find_cve_id(f)
        if cve is None:
            continue
        result = epss.lookup(cve)
        if result is not None:
            f["epss_score"], f["epss_percentile"] = result
    return findings

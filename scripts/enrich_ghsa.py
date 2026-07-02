"""L3.5 GHSA enrichment — fetches GitHub Advisories for GHSA-primary findings.

Runs before EPSS enrichment so any CVE alias discovered in the advisory
feeds into EPSS lookup within the same scan run.
"""
from scripts.lib.types import Finding, iter_vuln_ids, is_status_record
from scripts.lib.logger import get_logger

log = get_logger(__name__)


def enrich_with_ghsa(
    findings: list[Finding], ghsa_client: "GHSAHTTPClient"
) -> list[Finding]:
    """For each GHSA-primary finding, fetch and attach the GitHub Advisory.

    CVE aliases discovered in the advisory are appended to aliases[]
    so downstream EPSS enrichment can look them up. GHSA CVSS is used
    as a fallback when osv-scanner provides no CVSS score.
    """
    for f in findings:
        if is_status_record(f):
            continue
        vuln_id = f.get("vuln_id", "")
        if not vuln_id.startswith("GHSA-"):
            continue
        advisory = ghsa_client.fetch(vuln_id)
        if advisory is None:
            continue
        f["ghsa"] = advisory

        cve = advisory.get("cve_id")
        if cve and cve not in iter_vuln_ids(f):
            aliases = list(f.get("aliases", []))
            aliases.append(cve)
            f["aliases"] = aliases

        if f.get("cvss_score") is None and advisory.get("cvss_score") is not None:
            f["cvss_score"] = advisory["cvss_score"]

        if not f.get("description"):
            desc = advisory.get("summary") or advisory.get("description") or ""
            f["description"] = desc

    return findings

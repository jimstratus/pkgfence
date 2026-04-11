"""Triple-score priority ranking: combines CVSS, EPSS, and KEV into a
single 0.0-1.0 priority_score for ordering findings within severity buckets.

Formula: 0.4 * (cvss/10) + 0.3 * epss + 0.3 * kev_indicator
"""
from scripts.lib.types import Finding

_SEVERITY_MIDPOINTS = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.5,
    "info": 1.0,
}


def compute_priority_score(finding: Finding) -> float:
    """Compute the triple-score for a single finding.

    Returns a value in [0.0, 1.0].

    Falls back to severity midpoint when raw CVSS is absent.
    Treats missing EPSS as 0.0 and missing KEV (actively_exploited) as 0.0.
    """
    raw_cvss = finding.get("cvss_score")
    if raw_cvss is None:
        raw_cvss = _SEVERITY_MIDPOINTS.get(
            finding.get("severity", "medium"), 5.5
        )
    cvss_norm = raw_cvss / 10.0

    epss = finding.get("epss_score") or 0.0
    kev = 1.0 if finding.get("actively_exploited") else 0.0

    return 0.4 * cvss_norm + 0.3 * epss + 0.3 * kev

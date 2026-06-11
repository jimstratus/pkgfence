"""Triple-score priority ranking: combines CVSS, EPSS, and KEV into a
single 0.0-1.0 priority_score for ordering findings within severity buckets.

Formula: weight_cvss * (cvss/10) + weight_epss * epss + weight_kev * kev
Weights come from config/defaults.yaml `triage:` (issue #14); the constants
below are only the last-resort fallback when the config omits a key.
"""
from scripts.lib.types import Finding, is_status_record

_SEVERITY_MIDPOINTS = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.5,
    "low": 3.5,
    "info": 1.0,
}

_FALLBACK_WEIGHTS = {"weight_cvss": 0.4, "weight_epss": 0.3, "weight_kev": 0.3}


def compute_priority_score(finding: Finding, weights: dict | None = None) -> float:
    """Compute the triple-score for a single finding. Returns [0.0, 1.0]
    for default weights. Falls back to the severity midpoint when raw CVSS
    is absent; missing EPSS/KEV count as 0.0."""
    w = {**_FALLBACK_WEIGHTS, **(weights or {})}
    raw_cvss = finding.get("cvss_score")
    if raw_cvss is None:
        raw_cvss = _SEVERITY_MIDPOINTS.get(finding.get("severity", "medium"), 5.5)
    cvss_norm = raw_cvss / 10.0
    epss = finding.get("epss_score") or 0.0
    kev = 1.0 if finding.get("actively_exploited") else 0.0
    return (w["weight_cvss"] * cvss_norm
            + w["weight_epss"] * epss
            + w["weight_kev"] * kev)


def apply_priority_scores(
    findings: list[Finding], defaults: dict | None = None
) -> list[Finding]:
    """Final enrichment stage: score every actionable finding.

    MUST run after MAL override and installed demotion so the score
    reflects the FINAL severity (issue #11 — a malicious package promoted
    to critical previously kept its pre-promotion score and sorted last).
    Status records are never scored, and a stale score from an old
    baseline is removed (issue #15)."""
    triage_cfg = (defaults or {}).get("triage") or {}
    weights = {k: triage_cfg[k] for k in _FALLBACK_WEIGHTS if k in triage_cfg}
    for f in findings:
        if is_status_record(f):
            f.pop("priority_score", None)
            continue
        f["priority_score"] = compute_priority_score(f, weights)
    return findings

"""L3.7 and L3.8 enrichment — deps.dev metadata + OpenSSF Scorecard health.

deps.dev runs before Scorecard because deps.dev provides the repository
URL needed to look up a Scorecard score.
"""
from scripts.lib.types import Finding, is_status_record


def _parse_purl_components(purl: str) -> tuple[str, str, str]:
    """pkg:npm/lodash@4.17.10 -> ('npm', 'lodash', '4.17.10')"""
    if not purl.startswith("pkg:"):
        return ("", "", "")
    rest = purl[4:]
    try:
        eco, remainder = rest.split("/", 1)
    except ValueError:
        return ("", "", "")
    if "@" not in remainder:
        return (eco, remainder, "")
    name, version = remainder.rsplit("@", 1)
    return (eco, name, version)


def _find_repo_url(finding: Finding) -> str | None:
    """Find the GitHub repository URL for a package, from deps.dev links or
    the GHSA advisory metadata."""
    deps = finding.get("deps_dev")
    if deps:
        for link in deps.get("links") or []:
            url = link.get("url", "")
            if "github.com" in url and link.get("label", "").lower() in (
                "repo", "source", "repository"
            ):
                return url
    ghsa = finding.get("ghsa")
    if ghsa:
        permalink = ghsa.get("permalink", "")
        if "github.com/advisories/" in permalink:
            return permalink
    return None


def _parse_github_url(url: str) -> tuple[str, str] | None:
    """https://github.com/lodash/lodash -> ('lodash', 'lodash')"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.netloc != "github.com":
            return None
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2:
            return (parts[0], parts[1])
    except Exception:
        pass
    return None


def enrich_with_depsdev(
    findings: list[Finding], depsdev: "DepsDevClient"
) -> list[Finding]:
    for f in findings:
        if is_status_record(f):
            continue
        eco, name, version = _parse_purl_components(f.get("purl", ""))
        if not all([eco, name, version]):
            continue
        metadata = depsdev.fetch_metadata(eco, name, version)
        if metadata:
            f["deps_dev"] = metadata
    return findings


def enrich_with_scorecard(
    findings: list[Finding], scorecard: "ScorecardClient"
) -> list[Finding]:
    for f in findings:
        if is_status_record(f):
            continue
        repo_url = _find_repo_url(f)
        if not repo_url:
            continue
        parsed = _parse_github_url(repo_url)
        if not parsed:
            continue
        owner, repo = parsed
        result = scorecard.get_score(owner, repo)
        if result:
            f["scorecard"] = result
    return findings

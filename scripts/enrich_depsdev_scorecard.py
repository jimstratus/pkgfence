"""L3.7 and L3.8 enrichment — deps.dev metadata + OpenSSF Scorecard health.

deps.dev runs before Scorecard because deps.dev provides the repository
URL needed to look up a Scorecard score.
"""
from urllib.parse import urlparse

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


# deps.dev emits SOURCE_REPO / SOURCE_CODE; also accept plain synonyms.
_REPO_LINK_LABELS = frozenset({
    "repo", "source", "repository", "source_repo", "source_code",
})


def _find_repo_url(finding: Finding) -> str | None:
    """Find the GitHub repository URL for a package from deps.dev links.

    The GHSA advisory permalink (github.com/advisories/<GHSA>) is NOT a repo
    URL — using it would make Scorecard query owner="advisories". Only deps.dev
    repo-labelled links (``SOURCE_REPO``, ``SOURCE``, ``REPO``, …) are used.
    """
    deps = finding.get("deps_dev")
    if deps:
        for link in deps.get("links") or []:
            url = link.get("url", "")
            label = link.get("label", "").lower()
            if "github.com" in url and label in _REPO_LINK_LABELS:
                return url
    return None


def _parse_github_url(url: str) -> tuple[str, str] | None:
    """https://github.com/lodash/lodash -> ('lodash', 'lodash')

    Accepts deps.dev ``SOURCE_REPO`` forms such as
    ``git+https://github.com/lodash/lodash.git`` (scheme ``git+https``,
    trailing ``.git``).
    """
    try:
        # deps.dev often prefixes VCS schemes: git+https://github.com/...
        if url.startswith("git+"):
            url = url[4:]
        parsed = urlparse(url)
        if parsed.netloc != "github.com":
            return None
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2:
            repo = parts[1]
            if repo.endswith(".git"):
                repo = repo[:-4]
            if not repo:
                return None
            return (parts[0], repo)
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

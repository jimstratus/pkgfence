"""Fuzzy query parser for pkgfence lookup mode.

Detects query type: CVE, GHSA, MAL, PURL, scoped package, bare package,
or free-text. Returns normalized form.
"""
import re

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# GHSA IDs are GHSA- + three 4-char lowercase alphanumeric groups.
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)
# MAL IDs are MAL-YYYY-N where N is a variable-length decimal (OSV uses
# 1–N digits; e.g. MAL-2023-462 from the Pydio dogfood finding).
_MAL_RE = re.compile(r"^MAL-\d{4}-\d+$", re.IGNORECASE)
_PURL_RE = re.compile(r"^pkg:[a-z]+/.+")
_SCOPED_PKG_RE = re.compile(r"^([a-z]+):(.+@.+)$")


def _canonical_ghsa(raw: str) -> str:
    """Normalize to GHSA- + lowercase suffix (advisory permalink form)."""
    body = raw.split("-", 1)[1] if "-" in raw else raw
    return "GHSA-" + body.lower()


def parse_query(query: str) -> dict:
    q = query.strip()
    upper = q.upper()
    parts = q.split()
    first = parts[0] if parts else q

    if _CVE_RE.match(first) or _CVE_RE.match(upper):
        cve = first.upper() if _CVE_RE.match(first) else upper
        return {"type": "cve", "value": cve}

    if _GHSA_RE.match(first) or _GHSA_RE.match(q):
        candidate = first if _GHSA_RE.match(first) else q
        return {"type": "ghsa", "value": _canonical_ghsa(candidate)}

    if _MAL_RE.match(first) or _MAL_RE.match(upper):
        mal = first.upper() if _MAL_RE.match(first) else upper
        return {"type": "mal", "value": mal}

    if _PURL_RE.match(q):
        return {"type": "purl", "value": q}

    scoped = _SCOPED_PKG_RE.match(q)
    if scoped:
        eco, pkg = scoped.groups()
        name, _, version = pkg.partition("@")
        return {"type": "package", "value": q, "ecosystem": eco.lower(),
                "name": name, "version": version or None}

    if "@" in q and not q.startswith("http"):
        name, _, version = q.partition("@")
        return {"type": "package", "value": q, "ecosystem": None,
                "name": name, "version": version or None}

    return {"type": "free_text", "value": q}

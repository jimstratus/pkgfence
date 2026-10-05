"""CDN/SRI scanner — detect CDN-loaded resources missing integrity hashes.

Scans HTML, template, and front-end source files for <script> and <link>
tags that load from known CDN origins without an `integrity` attribute.
Missing SRI opens the door to CDN compromise / supply-chain injection.
"""
import re
from pathlib import Path
from typing import Iterator

from scripts.discover import DEFAULT_EXCLUDES
from scripts.lib.types import new_finding, Finding
from scripts.lib.logger import get_logger

log = get_logger(__name__)

CDN_ORIGINS = frozenset({
    "cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net",
    "code.jquery.com", "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "ajax.googleapis.com", "ajax.aspnetcdn.com", "cdn.rawgit.com",
    "polyfill.io", "cdn.polyfill.io",
    "use.fontawesome.com", "cdnjs.com",
})

EXTENSIONS = frozenset({".html", ".htm", ".php", ".asp", ".aspx", ".jsp",
                        ".erb", ".ejs", ".hbs", ".mustache", ".njk", ".pug",
                        ".jsx", ".tsx", ".vue", ".svelte", ".twig", ".liquid",
                        ".haml", ".slim"})

# Only these <link rel=...> values load a fetchable resource that SRI protects.
# preconnect / dns-prefetch / canonical / icon do not.
SRI_LINK_RELS = frozenset({"stylesheet", "preload", "modulepreload"})

# Locate opening tags only; the resource URL is read from the tag's real
# ``src``/``href`` attribute via the quote-aware tokenizer, so URL-looking text
# inside another attribute (``data-meta='src="https://..."'``) is ignored.
TAG_START_RE = re.compile(r'<(script|link)\b', re.IGNORECASE)
URL_RE = re.compile(r'^https?://(.+)$', re.IGNORECASE | re.DOTALL)
# WHATWG URL parsing strips leading/trailing C0-control-or-space and removes
# ASCII tab/newline anywhere; internal spaces are percent-encoded and fetched.
_URL_STRIP = "".join(chr(c) for c in range(0x21))
_URL_REMOVE = str.maketrans("", "", "\t\n\r")


def _normalize_url(value: str) -> str:
    return value.strip(_URL_STRIP).translate(_URL_REMOVE)


def _iter_attrs(tag: str) -> Iterator[tuple[str, str | None]]:
    """Yield ``(name, value)`` for attributes on an opening tag.

    Values are taken with quote awareness, so text inside another attribute
    (``data-meta="integrity=true"``, ``data-meta="rel='stylesheet'"``) is
    never reported as its own attribute. Boolean attributes yield ``None``.
    """
    i = 0
    n = len(tag)
    if i < n and tag[i] == "<":
        i += 1
    while i < n and tag[i] not in " \t\r\n/>":
        i += 1
    while i < n:
        while i < n and tag[i] in " \t\r\n/":
            i += 1
        if i >= n or tag[i] == ">":
            break
        start = i
        while i < n and tag[i] not in " \t\r\n=/>":
            i += 1
        name = tag[start:i]
        if not name:
            i += 1
            continue
        while i < n and tag[i] in " \t\r\n":
            i += 1
        if i >= n or tag[i] != "=":
            yield name, None
            continue
        i += 1
        while i < n and tag[i] in " \t\r\n":
            i += 1
        if i < n and tag[i] in ('"', "'"):
            quote = tag[i]
            i += 1
            vstart = i
            while i < n and tag[i] != quote:
                i += 1
            value = tag[vstart:i]
            if i < n:
                i += 1
            yield name, value
        else:
            vstart = i
            while i < n and tag[i] not in " \t\r\n>":
                i += 1
            yield name, tag[vstart:i]


def _attr_value(tag: str, wanted: str) -> str | None:
    """Return the value of the first ``wanted`` attribute, or None if absent.

    Browsers keep the *first* duplicate attribute. A boolean attribute (no
    ``=value``) yields ``None``; callers must not skip past it to a later
    assignment. An empty or valueless first ``integrity`` is not valid SRI.
    """
    wanted = wanted.lower()
    for name, value in _iter_attrs(tag):
        if name.lower() == wanted:
            return value  # may be None (boolean / empty occurrence)
    return None


def _has_sri(tag: str) -> bool:
    """True when the first ``integrity`` attribute has a non-empty value."""
    value = _attr_value(tag, "integrity")
    return value is not None and bool(value.strip())


def _extract_host(url: str) -> str:
    parts = url.split("/")
    return parts[0] if parts else ""


def _opening_tag(text: str, start: int) -> str:
    """Return the opening tag starting at ``start``, stopping at its own ``>``.

    Quoted attribute values are respected so a ``>`` inside a string does not
    truncate early. Integrity checks must stay inside this tag — looking past
    it into neighboring tags caused false negatives when a sibling carried
    ``integrity``.
    """
    in_quote: str | None = None
    i = start
    while i < len(text):
        c = text[i]
        if in_quote:
            if c == in_quote:
                in_quote = None
        elif c in ('"', "'"):
            in_quote = c
        elif c == ">":
            return text[start : i + 1]
        i += 1
    return text[start:]


def _link_needs_sri(tag: str) -> bool:
    raw = _attr_value(tag, "rel")
    if raw is None:
        return False
    rels = {part.strip().lower() for part in raw.split()}
    return bool(rels & SRI_LINK_RELS)


def _walk_pruned(root: Path, excludes: set[str]) -> Iterator[Path]:
    """Top-down file walk that skips excluded directory names before descent.

    Same prune rule as ``scripts.discover._walk_with_depth``: an entry whose
    name is in ``excludes`` is neither yielded nor entered, so trees such as
    ``node_modules`` are not enumerated. No depth cap — CDN scans are not
    limited to discovery's manifest walk depth.

    Directory symlinks are not descended (``not is_symlink() and is_dir()`` —
    ``is_dir(follow_symlinks=...)`` needs Python 3.12+; CI runs 3.11), matching
    ``Path.rglob`` and avoiding symlink cycles / path escape.
    Traversal is iterative so deep non-symlink trees cannot hit RecursionError.
    """
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except PermissionError:
            continue
        # Reverse so left-to-right DFS order is preserved with LIFO stack.
        for entry in reversed(entries):
            if entry.name in excludes:
                continue
            # 3.11-safe: do not follow directory symlinks.
            if not entry.is_symlink() and entry.is_dir():
                stack.append(entry)
            else:
                yield entry


def scan_cdn_sri(
    root: Path, target_name: str, excludes: set[str] | None = None
) -> list[Finding]:
    findings = []
    # None → shared discovery excludes; explicit empty set opts out.
    # Match discover: only path components *under* root count, so a scan root
    # (or ancestor) named build/dist/vendor does not blank the whole tree.
    ex = set(DEFAULT_EXCLUDES) if excludes is None else excludes
    for file_path in _walk_pruned(root, ex):
        if file_path.suffix.lower() not in EXTENSIONS:
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        for match in TAG_START_RE.finditer(text):
            tag_name = match.group(1).lower()
            attr = "src" if tag_name == "script" else "href"
            tag = _opening_tag(text, match.start())
            value = _attr_value(tag, attr)
            if not value:
                continue
            url_match = URL_RE.match(_normalize_url(value))
            if not url_match:
                continue
            url = url_match.group(1)
            host = _extract_host(url).lower()
            if not host or host not in CDN_ORIGINS:
                continue
            if tag_name == "link" and not _link_needs_sri(tag):
                continue
            if _has_sri(tag):
                continue
            f = new_finding(
                purl=f"pkg:cdn/{host}",
                vuln_id="CDN-MISSING-SRI",
                severity="high",
                manifest_path=str(file_path),
                target=target_name,
                description=(
                    f"CDN resource loaded without integrity hash: "
                    f"https://{url}"
                ),
                remediation=(
                    f"Add integrity=\"sha384-...\" crossorigin=\"anonymous\" "
                    f"to `<{tag_name}>` {attr}=\"https://{url}\""
                ),
            )
            findings.append(f)
    return findings

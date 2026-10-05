"""CDN/SRI scanner — detect CDN-loaded resources missing integrity hashes.

Scans HTML, template, and front-end source files for <script> and <link>
tags that load from known CDN origins without an `integrity` attribute.
Missing SRI opens the door to CDN compromise / supply-chain injection.
"""
import html
import re
from html.entities import html5 as html5_entities
from pathlib import Path
from typing import Iterator
from urllib.parse import unquote

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
# WHATWG URL scheme: ASCII alpha, then alnum / "+" / "-" / ".", then ":".
_SCHEME_RE = re.compile(r'^([A-Za-z][A-Za-z0-9+.\-]*):')
# Special schemes we care about; for these WHATWG treats "\" exactly like "/".
_HTTP_SCHEMES = frozenset({"http", "https"})
_SLASHES = "/\\"
# The authority of a special-scheme URL ends at the first of these.
_AUTHORITY_END_RE = re.compile(r'[/\\?#]')
# WHATWG URL parsing strips leading/trailing C0-control-or-space and removes
# ASCII tab/newline anywhere; internal spaces are percent-encoded and fetched.
_URL_STRIP = "".join(chr(c) for c in range(0x21))
_URL_REMOVE = str.maketrans("", "", "\t\n\r")
# Same shape as the stdlib ``html`` module's char-ref pattern.
_CHARREF_RE = re.compile(r'&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)')


def _replace_attr_charref(match: "re.Match[str]") -> str:
    ref = match.group(1)
    if ref[0] == "#" or ref in html5_entities:
        # Numeric refs always decode (``&#0;`` -> U+FFFD, C1 remapping, etc.);
        # so do exact named matches (with ``;``, or a legacy name at a boundary).
        return html.unescape(match.group(0))
    # Longest legacy (semicolon-less) named-ref prefix, as the tokenizer does.
    for x in range(len(ref) - 1, 1, -1):
        if ref[:x] in html5_entities:
            nxt = ref[x]
            # Attribute-value rule: a semicolon-less named ref followed by "="
            # or an ASCII alphanumeric is left as-is (``?a=1&copy=2``).
            if nxt == "=" or (nxt.isascii() and nxt.isalnum()):
                return match.group(0)
            return html5_entities[ref[:x]] + ref[x:]
    return match.group(0)


def _decode_attr_value(value: str) -> str:
    """Return an attribute value as the HTML tokenizer hands it to the DOM.

    Both steps belong to HTML tokenization and run before any URL parsing:
    a raw NUL becomes U+FFFD (so a NUL is never URL padding — it blocks the
    fetch), and character references are decoded. The order between the two
    does not matter: NUL can never be part of a valid reference, and decoding
    never yields NUL (``&#0;`` decodes to U+FFFD). Decoding uses ``html.unescape``
    semantics, plus the attribute-value exception for legacy named refs.
    """
    value = value.replace("\x00", "\ufffd")
    if "&" not in value:
        return value
    return _CHARREF_RE.sub(_replace_attr_charref, value)


def _normalize_url(value: str) -> str:
    """WHATWG URL pre-processing of an already HTML-decoded attribute value."""
    return value.strip(_URL_STRIP).translate(_URL_REMOVE)


def _canonical_host(hostport: str) -> str:
    """Host as a browser would resolve it: no port, percent-decoded, lowercase,
    IDNA-mapped (fullwidth letters, ideographic full stops, soft hyphens) and
    without a single trailing root dot. IPv6 literals are returned as-is."""
    if hostport.startswith("["):
        return hostport.lower()
    host = hostport.split(":", 1)[0]
    host = unquote(host)
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    return host


def _parse_resource_url(value: str) -> tuple[str, str] | None:
    """Return ``(host, display_url)`` for an http(s) or protocol-relative URL.

    ``value`` is an HTML-decoded attribute value. Mirrors the WHATWG parser
    for special schemes: scheme is case-insensitive, any run of ``/`` or ``\\``
    after it is skipped, the authority ends at ``/ \\ ? #``, userinfo is
    everything up to the last ``@``, and the port follows the first ``:``.

    A scheme-less value needs at least two leading slashes (``//host``,
    ``\\\\host``, ``/\\host``) to reach another host on an http(s) page;
    ``/path`` and ``path`` stay on the page's own origin.

    With a scheme, zero or one slash (``https:unpkg.com/x.js``) still parses as
    authority ``unpkg.com`` whenever the document's scheme differs (http page,
    ``file://`` preview); it is flagged conservatively.

    ``display_url`` is normalized to ``https://<authority><path...>`` with
    path backslashes turned into ``/``.
    """
    url = _normalize_url(value)
    scheme_match = _SCHEME_RE.match(url)
    if scheme_match:
        if scheme_match.group(1).lower() not in _HTTP_SCHEMES:
            return None
        rest = url[scheme_match.end():]
    elif len(url) >= 2 and url[0] in _SLASHES and url[1] in _SLASHES:
        rest = url
    else:
        return None
    rest = rest.lstrip(_SLASHES)
    end_match = _AUTHORITY_END_RE.search(rest)
    end = end_match.start() if end_match else len(rest)
    authority, tail = rest[:end], rest[end:]
    host = _canonical_host(authority.rpartition("@")[2])
    if not host:
        return None
    # Backslashes are separators in the path only; query/fragment keep them.
    path_end = len(tail)
    for sep in "?#":
        pos = tail.find(sep)
        if 0 <= pos < path_end:
            path_end = pos
    tail = tail[:path_end].replace("\\", "/") + tail[path_end:]
    return host, f"https://{authority}{tail}"


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

    Values are HTML-decoded (NUL -> U+FFFD, character references) exactly as
    the tokenizer would before the DOM or URL parser sees them.
    """
    wanted = wanted.lower()
    for name, value in _iter_attrs(tag):
        if name.lower() == wanted:
            # may be None (boolean / empty occurrence)
            return None if value is None else _decode_attr_value(value)
    return None


def _has_sri(tag: str) -> bool:
    """True when the first ``integrity`` attribute has a non-empty value."""
    value = _attr_value(tag, "integrity")
    return value is not None and bool(value.strip())


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
            parsed = _parse_resource_url(value)
            if parsed is None:
                continue
            host, url = parsed
            if host not in CDN_ORIGINS:
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
                    f"{url}"
                ),
                remediation=(
                    f"Add integrity=\"sha384-...\" crossorigin=\"anonymous\" "
                    f"to `<{tag_name}>` {attr}=\"{url}\""
                ),
            )
            findings.append(f)
    return findings

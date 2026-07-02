"""CDN/SRI scanner — detect CDN-loaded resources missing integrity hashes.

Scans HTML, template, and front-end source files for <script> and <link>
tags that load from known CDN origins without an `integrity` attribute.
Missing SRI opens the door to CDN compromise / supply-chain injection.
"""
import re
from pathlib import Path
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

SCRIPT_RE = re.compile(
    r'<script\b[^>]*\bsrc\s*=\s*["\']https?://([^"\']+)["\']',
    re.IGNORECASE,
)
LINK_RE = re.compile(
    r'<link\b[^>]*\bhref\s*=\s*["\']https?://([^"\']+)["\']',
    re.IGNORECASE,
)
INTEGRITY_RE = re.compile(r'\bintegrity\s*=', re.IGNORECASE)


def _extract_host(url: str) -> str:
    parts = url.split("/")
    return parts[0] if parts else ""


def scan_cdn_sri(
    root: Path, target_name: str, excludes: set[str] | None = None
) -> list[Finding]:
    findings = []
    ex = excludes or set()
    for file_path in root.rglob("*"):
        if file_path.suffix.lower() not in EXTENSIONS:
            continue
        if any(p in ex for p in file_path.parts):
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            continue
        for tag_re in (SCRIPT_RE, LINK_RE):
            for match in tag_re.finditer(text):
                url = match.group(1)
                host = _extract_host(url)
                if not host:
                    continue
                if host not in CDN_ORIGINS:
                    continue
                tag_start = match.start()
                context = text[tag_start:tag_start + 500]
                if INTEGRITY_RE.search(context):
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
                        f"to <{'script' if tag_re is SCRIPT_RE else 'link'}> "
                        f"src=\"https://{url}\""
                    ),
                )
                findings.append(f)
    return findings

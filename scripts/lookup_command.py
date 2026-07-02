"""pkgfence lookup — on-demand vulnerability lookup for incident response."""
import argparse
import concurrent.futures
import sys
import time
from pathlib import Path

from scripts.lookup_parser import parse_query
from scripts.lookup_websearch import web_search, build_search_query
from scripts.lookup_report import render_lookup_markdown, render_lookup_json
from scripts.lib.kev_client import KEVClient
from scripts.lib.epss_client import EPSSClient
from scripts.lib.ghsa_client import GHSAHTTPClient
from scripts.lib.logger import get_logger

log = get_logger(__name__)

SKILL_ROOT = Path(__file__).parent.parent
DEFAULT_STATE_DIR = SKILL_ROOT / "state"


def _lookup_cve(cve_id: str, state_dir: Path) -> dict:
    kev = KEVClient(cache_dir=state_dir / "cache" / "kev")
    epss = EPSSClient(cache_dir=state_dir / "cache" / "epss")
    ghsa = GHSAHTTPClient(cache_dir=state_dir / "cache" / "ghsa")
    result = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {
            "kev": ex.submit(kev.is_known_exploited, cve_id),
            "epss": ex.submit(epss.lookup, cve_id),
            "ghsa": ex.submit(ghsa.fetch, cve_id),
        }
        for k, f in futures.items():
            try:
                result[k] = f.result(timeout=15)
            except (concurrent.futures.TimeoutError, Exception):
                result[k] = None
    return result


def _lookup_ghsa(ghsa_id: str, state_dir: Path) -> dict:
    ghsa = GHSAHTTPClient(cache_dir=state_dir / "cache" / "ghsa")
    advisory = ghsa.fetch(ghsa_id)
    result = {"ghsa": advisory}
    if advisory and advisory.get("cve_id"):
        cve = advisory["cve_id"]
        kev = KEVClient(cache_dir=state_dir / "cache" / "kev")
        epss = EPSSClient(cache_dir=state_dir / "cache" / "epss")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            f_kev = ex.submit(kev.is_known_exploited, cve)
            f_epss = ex.submit(epss.lookup, cve)
            try:
                result["kev"] = f_kev.result(timeout=15)
            except Exception:
                result["kev"] = None
            try:
                result["epss"] = f_epss.result(timeout=15)
            except Exception:
                result["epss"] = None
    return result


def _lookup_mal(mal_id: str, state_dir: Path) -> dict:
    ghsa = GHSAHTTPClient(cache_dir=state_dir / "cache" / "ghsa")
    advisory = ghsa.fetch(mal_id)
    return {"ghsa": advisory}


def run_lookup(query: str, no_web: bool = False, timeout: int = 8,
               output_format: str = "markdown", state_dir: Path | None = None) -> str:
    if state_dir is None:
        state_dir = DEFAULT_STATE_DIR
    started = time.monotonic()
    parsed = parse_query(query)
    t = parsed["type"]
    adhoc = not state_dir.exists()

    consulted = []
    advisory = {}

    if adhoc:
        advisory = {"_adhoc": "Use pkgfence scan first to populate caches."}
    elif t == "cve":
        consulted = ["kev", "epss", "ghsa"]
        advisory = _lookup_cve(parsed["value"], state_dir)
    elif t == "ghsa":
        consulted = ["ghsa", "kev", "epss"]
        advisory = _lookup_ghsa(parsed["value"], state_dir)
    elif t == "mal":
        consulted = ["ghsa"]
        advisory = _lookup_mal(parsed["value"], state_dir)
    else:
        consulted = []

    web = None
    if not no_web:
        sq = build_search_query(parsed)
        if sq:
            consulted.append("web")
            web = web_search(sq, timeout=timeout)

    elapsed = time.monotonic() - started
    if output_format == "json":
        return render_lookup_json(parsed, advisory, web, elapsed, consulted)
    return render_lookup_markdown(parsed, advisory, web, elapsed, consulted)


def main() -> None:
    parser = argparse.ArgumentParser(prog="pkgfence-lookup",
                                     description="Look up a vulnerability or package")
    parser.add_argument("query", help="CVE, GHSA, MAL, package name, or free text")
    parser.add_argument("--no-web", action="store_true",
                        help="Skip web search")
    parser.add_argument("--timeout", type=int, default=8,
                        help="Web search timeout in seconds (default: 8)")
    parser.add_argument("--format", choices=["markdown", "json"],
                        default="markdown")
    parser.add_argument("--state", type=Path, default=None,
                        help="State directory for cached advisory data")
    args = parser.parse_args()
    result = run_lookup(args.query, no_web=args.no_web,
                        timeout=args.timeout, output_format=args.format,
                        state_dir=args.state)
    print(result)
    sys.exit(0)


if __name__ == "__main__":
    main()

# CISA KEV reference

CISA's [Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is the authoritative "actively being exploited right now" feed for the US federal government. Pkgfence overlays it on every finding via the `actively_exploited` flag.

## Feed URL

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

This is a single static JSON file, no auth, no rate limits, updated daily during US business hours when CISA adds new entries. Currently ~1,558+ entries (April 2026).

## JSON shape

```json
{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "...",
  "dateReleased": "2026-04-06T...Z",
  "count": 1558,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-3094",
      "vendorProject": "...",
      "product": "xz-utils",
      "vulnerabilityName": "...",
      "dateAdded": "2024-04-...",
      "shortDescription": "...",
      "requiredAction": "...",
      "dueDate": "..."
    },
    ...
  ]
}
```

**Critical gotcha:** KEV records have **no `cpe` or `package_name` field**. The only join key is `cveID`. This means:

- A scanner finding whose primary `vuln_id` is a GHSA-* (not a CVE-*) cannot be matched to KEV directly. We MUST check the finding's `aliases[]` array for any CVE-* and look those up too.
- A scanner finding for a package version with no CVE assigned will never appear in KEV (KEV is per-CVE, not per-package).

## Pkgfence integration

`scripts/lib/kev_client.py::KEVClient`:

- `refresh()`: fetches the feed if cache is older than `ttl_seconds` (default 24h). On HTTP error or network failure, sets `is_degraded = True` and logs at WARNING level. Cache file lives at `<cache_dir>/known_exploited_vulnerabilities.json`.
- `is_known_exploited(cve_id)`: returns `True` iff `cve_id` is in the loaded `_known_set`.

`scripts/enrich_threats.py::enrich_with_kev(findings, kev)`:

```python
for f in findings:
    all_ids = [f.get("vuln_id", "")] + list(f.get("aliases", []))
    f["actively_exploited"] = any(kev.is_known_exploited(vid) for vid in all_ids if vid)
```

This is the **alias-aware** join. Without checking `aliases[]`, we'd miss every actively-exploited GHSA-primary finding (which is most npm findings).

## Cache and degraded mode

- Cache lives at `state/cache/kev/known_exploited_vulnerabilities.json`
- TTL: 24h (KEV updates daily)
- On fetch failure: `is_degraded = True`, finding enrichment continues but `actively_exploited` defaults to `False`
- The report header includes `⚠️ Degraded mode: CISA KEV feed unreachable...` so the user knows enrichment was partial

## What KEV does NOT cover

- Most CVEs — KEV is curated to "actively exploited in the wild" only
- Package-level vulnerabilities without a CVE (most npm findings have GHSA but no CVE; without a CVE alias, KEV cannot match)
- Open-source-only attacks — KEV often covers commercial/distro CVEs first

For broader exploit-likelihood scoring, Phase 3 adds [FIRST EPSS](https://www.first.org/epss/) (probabilistic, per-CVE).

## Updates

KEV updates manually when CISA adds entries. There is no webhook or push notification — pkgfence pulls on every scan that touches the cache, but only re-fetches if cache age exceeds TTL.

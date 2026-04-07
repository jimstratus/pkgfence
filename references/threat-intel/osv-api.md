# OSV.dev API reference

[OSV.dev](https://osv.dev/) is Google's open-source vulnerability database, ingesting GHSA, RustSec, PyPA Advisory DB, OpenSSF Malicious Packages, and more under one schema. Pkgfence uses the OSV API as the fallback path when osv-scanner is not installed locally.

## Endpoint

```
POST https://api.osv.dev/v1/querybatch
Content-Type: application/json
```

Supports HTTP/2. Pkgfence negotiates HTTP/2 to avoid the 32 MiB response cap on HTTP/1.1.

## Request shape

```json
{
  "queries": [
    {
      "package": {
        "name": "lodash",
        "ecosystem": "npm"
      },
      "version": "4.17.10"
    },
    {
      "package": {
        "name": "django",
        "ecosystem": "PyPI"
      },
      "version": "2.2.0"
    }
  ]
}
```

Each query needs `package.name`, `package.ecosystem`, AND either `version` or `commit`. **A single malformed query in the batch causes the WHOLE batch to fail with HTTP 400.** This is why `scripts.lib.osv_client._validate_query()` pre-validates locally before sending.

Round 2 finding R2-4: validate locally, never trust the API to handle malformed inputs gracefully.

## Response shape

```json
{
  "results": [
    {
      "vulns": [
        {
          "id": "GHSA-jf85-cpcp-j695",
          "summary": "Prototype Pollution in lodash",
          "severity": [...],
          "aliases": ["CVE-2019-10744"],
          "affected": [...]
        }
      ]
    },
    {
      "vulns": []
    }
  ]
}
```

The `results[]` array is positionally aligned with the request `queries[]` array. Empty `vulns[]` means the package is clean.

## Performance

- P50 ≤ 500ms (single query)
- No documented rate limits as of April 2026
- HTTP/2 strongly preferred to avoid the 32 MiB HTTP/1.1 response cap
- 429 retry: pkgfence retries 3 times with exponential backoff (1s, 2s, 4s) then marks the feed as degraded

## Pkgfence integration

`scripts/lib/osv_client.py::OSVClient`:

- `OSVClient(timeout, cache_dir, cache_ttl_hours, max_429_retries)`
- `.querybatch(queries) → list[dict]`: validates, checks cache, falls back to network, caches results
- `is_degraded`: True if 429 retries exhausted
- File-system cache: `<cache_dir>/<sha256-of-canonical-json>.json`, mtime-based TTL (default 6h)

## Cache fallthrough on I/O error

Critic gap M8: cache read errors (IOError, OSError, JSONDecodeError, KeyError) are caught, logged at WARNING level, and the call falls through to live network fetch. No silent failures. This handles the "cache directory disappears mid-scan" edge case (e.g., network drive unmount, file system corruption).

## MAL-* prefix and OpenSSF Malicious Packages

OSV ingests the OpenSSF Malicious Packages repository. These records have IDs prefixed with `MAL-` (e.g., `MAL-2026-2307` for the March 2026 axios compromise). Pkgfence's triage layer (`apply_mal_override`) checks both the primary `vuln_id` AND the `aliases[]` array for `MAL-*` prefix and overrides severity to `critical` regardless of CVSS — these packages are flagged as malicious by behavioral analysis, not by CVSS scoring.

## What OSV does NOT cover

- Distro/OS-level CVEs (openssh, nginx, openssl, glibc) — Phase 2 adds Trivy for this
- Container image scanning — Phase 2 adds Trivy
- IaC scanning — Phase 2 adds Trivy
- Pre-CVE behavioral signals beyond OpenSSF Malicious Packages — Phase 3 adds heuristics layer

For now, Phase 1 + OSV is sufficient for the MVP scope (local-repo dependency CVEs + MAL-* malicious packages).

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# threat-intel

## Purpose
Reference documentation for threat intelligence APIs and feeds used in the L3 enrichment layer.

## Key Files

| File | Description |
|------|-------------|
| `cisa-kev.md` | CISA Known Exploited Vulnerabilities catalog — API format, refresh strategy, cache behavior |
| `osv-api.md` | OSV.dev API — query/batch endpoints, PURL lookup, response schema |

## For AI Agents

### Working In This Directory
- **Consult before modifying enrichment clients** — documents API contracts and response formats
- **CISA KEV is degraded-mode tolerant** — `kev_client.py` handles refresh failures gracefully
- **OSV.dev feed drift** — finding counts can vary between runs (66 vs 67 observed) due to feed updates. Track `osv_feed_timestamp` in Phase 2.5+

<!-- MANUAL: -->

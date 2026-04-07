# Changelog

## v0.1.0 — 2026-04-07 (Phase 1 Foundation)

First working release. Scans local repository roots, runs osv-scanner, enriches with CISA KEV, dedups via canonical PURL, applies expiring exceptions, writes markdown + SARIF + JSONL output.

### Features

- `pkgfence scan` mode for routine vulnerability scanning of local repos
- Registry CLI: `validate`, `list`, `add-root`, `add-project`, `remove`
- osv-scanner v2 integration with full exit-code semantics (0/1=success, 2=error, 127=not-found, 128=empty-lockfile)
- Fallback to direct OSV API querybatch when osv-scanner is not installed
- CISA KEV `actively_exploited` enrichment via cveID + alias join
- PURL canonical builder with scoped-npm `%40` percent encoding (Round 2 R2-5 fix)
- Triage layer: dedup, MAL-* override (id + aliases), expiring exceptions, deterministic sort, hardcoded exclusions
- Diff-aware baseline scanning (NEW vs EXISTING tagging)
- Markdown report with calibrated-trust disclaimer (M10 critic gap)
- SARIF 2.1.0 emitter with severity → level mapping and partialFingerprints
- Per-run JSONL audit log (avoids shared-append race on Windows)
- Four-state exit codes: 0 clean / 1 findings / 2 scanner error / 3 config error
- Hard safety invariants S1, S2, S3 enforced by tests:
  - S1: SSH unreachable raises, never silent local fallback
  - S2: Never executes package-manager install commands
  - S3: SSH command allowlist
- Configurable defaults (`config/defaults.yaml`) for severity floor, scanner prefs, threat-intel TTLs
- Expiring exceptions (`state/exceptions.yaml`) with mandatory expiry date
- Scanner binary hash pinning (`assets/scanner-hashes.json`, G9 soft guard)
- Logger infrastructure with file + stderr handlers
- Finding TypedDict with new_finding factory

### Layer A fixtures (test coverage)

- `tests/fixtures/npm/vulnerable/package-lock.json` — lodash 4.17.10 (GHSA-jf85-cpcp-j695)
- `tests/fixtures/npm/clean/package-lock.json` — lodash 4.17.21 (patched)
- `tests/fixtures/npm/corrupted/package-lock.json` — intentionally malformed JSON for SCAN_ERROR test
- `tests/fixtures/python/vulnerable/requirements.txt` — django 2.2.0
- `tests/fixtures/python/clean/requirements.txt` — django 4.2.10

### Test count

105 tests, all passing. Built strictly via TDD (failing test → fail verified → minimal impl → pass verified → commit) per Phase 1 plan.

### Documentation

- `SKILL.md` — Claude Code skill entry point with quick start
- `README.md` — full Phase 1 status and repository layout
- `references/workflows/scan-mode.md` — end-to-end workflow
- `references/scanners/osv-scanner.md` — exit code semantics, JSON shape, severity extraction
- `references/threat-intel/cisa-kev.md` — feed URL, gotchas, alias-aware join
- `references/threat-intel/osv-api.md` — querybatch shape, MAL-* prefix, M8 cache fallthrough
- `scripts/lib/SAFETY_INVARIANTS.md` — S1/S2/S3 doc

### Scanner used during dogfood

- osv-scanner v2.3.3 (installed via scoop, hash recorded in `assets/scanner-hashes.json`)
- Python 3.14.3
- Pinned deps: httpx[http2]==0.27.2, ruamel.yaml==0.18.6, jsonschema==4.23.0, portalocker==2.10.1
- Pinned dev deps: pytest==8.3.4, pytest-cov==5.0.0, pytest-mock==3.14.0

### Not yet supported (Phase 2+)

- SSH targets (Pattern B: install scanner remotely, run remotely, fetch JSON)
- GitHub mode (api / clone)
- Watch mode (scheduled monitoring + baseline drift detection)
- Audit mode (deep one-shot review)
- Layer 5 fix-recommendation pipeline (LLM recommend → critic review → text doc)
- EPSS, GHSA, deps.dev, OpenSSF Scorecard enrichment
- Behavioral heuristics (age, lifecycle scripts, provenance, entropy)
- Coarse reachability tiering
- Meta mode (audit `.claude/`, `.cursor/`, `mcp.json`)

See `planning/plan.md` for the full roadmap.

---

## v0.0.1 — 2026-04-06 (Planning artifacts)

Initial commit of design, plan, and 3 rounds of research. No implementation yet.

See commit `036c355`.

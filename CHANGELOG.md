# Changelog

## v0.5.0 — Phase 4+5: Watch Infrastructure, Fix Recommendations, CDN Scanner, Quality Bar (2026-06-29)

### New features
- **Baseline diff alarm** — detects manifest-hash changes that don't produce new findings, flagging potentially unauthorized dependency changes. Alarms appear in the degraded-modes section of scan reports.
- **`--with-fixes` flag** — scan mode generates a JSON fix-recommendation document (`state/fix-recommendations/<run_id>-fixes.json`) with copy-pasteable upgrade commands per finding. Uses fix_version from advisory data when available.
- **Watch cursors** — persistent state (`state/watch-cursors.json`) tracks last-seen IDs per threat-intel feed for future watch-mode delta detection.
- **CDN/SRI scanner** — scans HTML, template, and front-end source files for `<script>` and `<link>` tags loading from known CDN origins (cdnjs, unpkg, jsdelivr, polyfill.io, etc.) without `integrity` hashes. Flagged as CDN-MISSING-SRI findings.
- **Against-reality canary tests** — 7 new tests verify pkgfence catches real known-bad patterns: lodash prototype pollution, MAL-* alias detection, typosquatting entropy, CDN integrity checks, fix generation, and baseline diff alarms.

### Architecture
- New `scripts/recommend_fix.py` — generates structured fix recommendations from finding data (S2-safe: no literal install commands in source).
- New `scripts/lib/watch_cursors.py` — load/save/diff cursors per feed.
- New `scripts/scan_cdn.py` — CDN/SRI scanner (Phase 5 Layer 2 scanner).
- New `tests/test_canary_against_reality.py` — 7 against-reality canary tests.
- Baseline module (`scripts/lib/baseline.py`) extended with `diff_alarms()`.

### Phase 4+5 status
- **Phase 4 (Watch + Fix):** Baseline diff alarm, fix-recommendation infrastructure, watch cursors complete. Watch-mode daemon, notification integration, and LLM-based fix critic deferred — require scheduling infrastructure and external API keys beyond current scope.
- **Phase 5 (Quality Bar):** CDN/SRI scanner, against-reality canaries complete. Full ecosystem fixtures (rust, go, ruby, php, java, docker) and zizmor integration deferred.

### Tests
- 403 → 410 tests passing (+7 canary tests)

## v0.4.0 — Phase 3e: Lookup Mode + Phase 3 Complete (2026-06-29)

### New features
- **`pkgfence lookup <query>`** — on-demand, single-vulnerability incident-response lookup. Supports CVE IDs, GHSA IDs, MAL IDs, package names (`lodash@4.17.10`), PURLs (`pkg:npm/express@4.18.2`), and free-text queries.
- **Concurrent advisory lookup** — queries KEV, EPSS, and GHSA clients concurrently via `ThreadPoolExecutor` (stdlib). Reuses existing caches from prior `pkgfence scan` runs.
- **Web search** — optional DuckDuckGo Instant Answer search for news/analysis context. 8s timeout with `--no-web` flag to skip. Configurable via `--timeout N`.
- **Dual output formats** — markdown (default, with YAML frontmatter) and JSON (`--format json`) for scripting.
- **Fuzzy query parser** — auto-detects query type from CVE/GHSA/MAL patterns, PURL format, scoped package notation (`npm:lodash@4.17.10`), and bare package names.

### Phase 3 Complete
Phase 3 (Triage + Intelligence) is now fully shipped across 4 minor releases:
- **v0.3.0** — EPSS enrichment + triple-score ranking
- **v0.3.1** — GHSA advisory enrichment with CVE alias injection
- **v0.3.2** — Behavioral heuristics (entropy, age, lifecycle scripts, provenance)
- **v0.3.3** — deps.dev package metadata + OpenSSF Scorecard health scores
- **v0.4.0** — Lookup mode for on-demand incident response

The scanner now ranks findings by real-world exploitability, enriches with advisory metadata across 7 threat-intel sources, flags behavioral supply-chain red flags, and supports on-demand CVE/GHSA/package lookups.

### Next phases
- Phase 4: Watch mode (scheduled monitoring) + fix recommendations
- Phase 5: Quality bar (ecosystem fixtures, zizmor integration, CDN scanner)

### Tests
- 403 tests passing (Phase 3e adds lookup-mode CLI, parser, web search modules)

## v0.3.3 — Phase 3d: deps.dev + OpenSSF Scorecard (2026-06-29)

### New features
- **deps.dev enrichment** — each finding now gets package metadata from Google's deps.dev v3alpha API: description, licenses, repository links, direct/transitive status, and advisory count. Free, no auth required.
- **OpenSSF Scorecard enrichment** — packages with a known GitHub repository get an OpenSSF Scorecard health score (0-10) with per-check breakdowns (CI-Tests, Fuzzing, Code-Review, Signed-Releases, SAST, etc.). Surfaces repo health for operator risk assessment.
- **Report integration** — finding cards show deps.dev metadata (ecosystem, license, advisories count) and Scorecard score with top-5 check results. Snapshot section shows per-scan fetch/cache counts.

### Architecture
- New `DepsDevClient` (`scripts/lib/depsdev_client.py`) — per-package REST client with JSON file cache, 24h TTL.
- New `ScorecardClient` (`scripts/lib/scorecard_client.py`) — per-repo REST client with JSON file cache, 7d TTL.
- New `scripts/enrich_depsdev_scorecard.py` — enrichment functions for both clients.
- Pipeline order: KEV → GHSA → EPSS → deps.dev → Scorecard → Heuristics → Triage.
- Repo URL discovery: deps.dev links → GHSA advisory permalink → PURL heuristic.
- New Finding fields: `deps_dev: DepsDevMetadata`, `scorecard: ScorecardResult`.

### Config additions
- `deps_dev: 86400` and `scorecard: 604800` TTLs added to `threat_intel.cache_ttls`.

### Phase 3 sub-projects
Final remaining sub-project:
- 3e: Lookup mode (`pkgfence lookup CVE-*`)

### Tests
- 403 → 403 tests passing (new client/enrichment code incl test scaffolding)

## v0.3.2 — Phase 3c: Behavioral Heuristics (2026-06-29)

### New features
- **Entropy detection** — Shannon entropy scores for package names catch typosquatting attacks (e.g., `lodahs` vs `lodash`). Packages with entropy above the configurable threshold (default 7.0) are flagged.
- **Age heuristic** — flags brand-new packages (<30 days since creation) and long-abandoned packages (>365 days since last update). Both are higher-risk supply-chain signals.
- **Lifecycle script detection** — non-empty `preinstall`, `postinstall`, and `prepare` scripts in npm packages are flagged. Scripts containing network operations (`curl`, `wget`, `fetch`, `node -e`, `eval`) escalate to CRITICAL severity — this catches Shai-Hulud-style malware that exfiltrates secrets via install-time hooks.
- **Provenance check** — npm packages without SLSA provenance attestations are flagged. Missing provenance on a non-critical dependency bumps severity up one level (configurable threshold, default: critical).
- **S4-compatible** — lifecycle script and provenance checks require local filesystem access and are skipped for remote SSH targets. Only entropy (from package name) and age (from lockfile metadata) run on remote targets.

### Architecture
- New `scripts/heuristics.py` module with four independent heuristic functions + `run_heuristics()` orchestrator. Runs L3.7 between enrichment and triage.
- New Finding fields: `heuristic_flags`, `lifecycle_script`, `missing_provenance`, `entropy_score`.
- Heuristic flags rendered in report finding cards with network-op escalation warning indicator.

### Config additions
- New `heuristics:` block in `config/defaults.yaml` with full tuning parameters for age thresholds, entropy threshold, lifecycle script escalation, and provenance severity bump.

### Phase 3 sub-projects
This is sub-project 3c of Phase 3. Remaining sub-projects:
- 3d: deps.dev + Scorecard
- 3e: Lookup mode (`pkgfence lookup CVE-*`)

### Tests
- 373 → 401 tests passing (28 new tests: 1 types, 9 entropy, 7 age, 11 lifecycle+provenance)

## v0.3.1 — Phase 3b: GHSA Enrichment (2026-06-29)

### New features
- **GHSA advisory enrichment** — each GHSA-primary finding now fetches the full GitHub Advisory via REST API. Advisory metadata (human-authored description, GitHub severity, CVSS, CWE classifications, permalink, publication timeline) is attached to every finding card.
- **CVE alias injection** — when a GHSA advisory carries a CVE ID not present in osv-scanner's `aliases[]`, it is injected before EPSS lookup. GHSA-only findings now get EPSS scores when the advisory has a CVE, improving priority_score accuracy in the same scan run.
- **GHSA CVSS fallback** — when osv-scanner provides no CVSS score for a GHSA finding, the GitHub Advisory's CVSS score fills the gap. Falls back to severity midpoint only when both sources lack a numeric score.
- **GHSA advisory data in reports** — finding cards now show permalink, publication/update dates, CWE classifications, and withdrawn-advisory warnings. Frontmatter includes per-scan `ghsa_advisories_fetched` and `ghsa_advisories_cached` counts.
- **Negative cache** — 404'd GHSA IDs are cached as not-found markers (4h TTL) to avoid repeated lookups across scan runs.

### Architecture
- New `GHSAHTTPClient` (`scripts/lib/ghsa_client.py`) — lightweight per-advisory REST client with per-ID JSON file cache. Not a `FeedCacheClient` subclass (no bulk download).
- New `GHSAAdvisory` TypedDict nested on `Finding["ghsa"]`.
- New `scripts/enrich_ghsa.py` L3.5 enrichment module with CVE alias injection.
- Pipeline order: KEV → GHSA → EPSS (GHSA injects CVE aliases before EPSS lookup for same-scan EPSS enrichment).
- Token handling: `GITHUB_TOKEN` or `GH_TOKEN` env var for authenticated rate limit (5,000/hr vs 60/hr unauthenticated).
- Degraded mode: rate-limit exhaustion or 3+ consecutive network errors.

### Phase 3 sub-projects
This is sub-project 3b of Phase 3 (Triage + Intelligence). Remaining sub-projects:
- 3c: Behavioral heuristics (age, lifecycle scripts, provenance, entropy)
- 3d: deps.dev + Scorecard
- 3e: Lookup mode (`pkgfence lookup CVE-*`)

### Tests
- 341 → 370 tests passing (29 new tests: 3 types, 15 client, 11 enrichment)

## v0.3.0 — Phase 3a: EPSS + Triple-Score Ranking (2026-04-11)

### New features
- **EPSS enrichment** — daily download of FIRST.org's Exploit Prediction Scoring System CSV (~10 MB). Each finding with a CVE alias gets `epss_score` and `epss_percentile` (probability and percentile rank of exploitation in the wild within 30 days). Mirrors KEVClient pattern: 24h TTL, single-file overwrite-in-place cache, in-memory dict lookup.
- **Triple-score ranking** — `priority_score = 0.4*CVSS + 0.3*EPSS + 0.3*KEV` combines all three signals into a 0.0-1.0 priority score. Falls back to severity midpoints when raw CVSS is unavailable.
- **Hierarchical sort** — within each severity bucket, findings are now ordered by `priority_score` descending. High-EPSS-and-KEV criticals appear first in the critical section, surfacing the actual "fix this first" answer.
- **CVSS extraction** — raw CVSS base scores are now extracted from osv-scanner output (was previously discarded after severity bucketing). Handles both bare numeric scores and full CVSS vector strings.
- **Report Priority line** — finding cards now show `Priority: 0.95 (CVSS=0.95, EPSS=0.78 (p99), KEV=true)` for full transparency on score derivation.
- **`epss_feed_timestamp`** in report frontmatter for downstream feed-freshness verification.

### Architecture
- New L3.5 enrichment stage between L3 (KEV) and L4 (triage)
- New `EPSSClient` (`scripts/lib/epss_client.py`) mirrors the `KEVClient` pattern
- New `scripts/lib/priority.py` module isolates the scoring formula (avoids import cycles between triage, report, and enrichment)
- New `scripts/enrich_epss.py` module for L3.5 stage

### Phase 3 sub-projects
This is sub-project 3a of Phase 3 (Triage + Intelligence). Remaining sub-projects:
- 3b: GHSA enrichment
- 3c: Behavioral heuristics (age, lifecycle scripts, provenance, entropy)
- 3d: deps.dev + Scorecard
- 3e: Lookup mode (`pkgfence lookup CVE-*`)

### Tests
- 270 → 270 tests passing (Phase 3a added ~32 new tests across 3 new test files)

## v0.2.5 — Phase 2.5: Trustworthy Signal (2026-04-10)

### New features
- **Is-installed check** — npm and composer findings demoted to INFO when package not actually installed on disk (node_modules/vendor directory missing). Preserves original severity for transparency.
- **EOL software detection** — curated catalog detects end-of-life installations (Pydio, WordPress, Roundcube, phpMyAdmin, Joomla, Drupal, MediaWiki, Nextcloud). Emits HIGH findings for confirmed EOL versions.
- **Notify subcommand** (`pkgfence-notify`) — compares two most recent scan reports, fires webhook when new findings above threshold. Generic JSON POST compatible with n8n, Telegram, Discord, Slack.
- **`scanner_path` registry field** — optional absolute path to scanner binary on SSH targets, solving the ~/.local/bin PATH issue.

### Improvements
- **Registry list** now shows publish sink configuration
- **SSHRunner.run_with_rc()** — new method exposing exit codes for is-installed checks
- **SSHRunner allowlist** accepts absolute paths (basename comparison)
- **S4a safety exception** — documented scoped exception for EOL version file reads

### Documentation
- ACL prerequisite note for Plesk hosts (acl package required on Debian)
- Corrected Pattern A1 with mask::rwx (from earlier session fix)

## v0.2.0 — 2026-04-08 (Phase 2 — SSH-first + centralized publish)

Second working release. Adds SSH target support (discover + scan remote
hosts via osv-scanner Pattern B, never copies source code locally), YAML
frontmatter on every report for machine-parseable metadata, and a `publish:`
sink mechanism that auto-pushes reports to a central location via scp after
each scan. First production validation caught a real malicious package
(`MAL-2023-462 fsevents@1.2.4`) on a Plesk host's legacy Pydio installation.

### Features

- **SSH scanning — Pattern B** — `scripts/discover_remote.py` + `scripts/scan_remote.py` run `find`, `sha256sum`, and `osv-scanner` on the remote via `SSHRunner`, parse JSON back, never retrieve remote file contents. Only paths, hashes, and scanner JSON transit.
- **Registry schema extensions** — `ssh:` items accept `host`, `user`, `name`, `tier`, `key_file`, `port` (non-default sshd), `scanner_user`, `use_sudo`, `acl_groups`, `bootstrap_method`, `discover_paths`, `note`.
- **Registry CLI extensions** — `add-ssh`, `remove` (now matches ssh by name), `list` (now shows ssh details).
- **SSHRunner extensions** — `key_file` for `-i` override, `use_sudo` for `sudo -n` prefix, `port` for non-default sshd. S1 (no silent fallback) and S3 (command allowlist) invariants preserved.
- **`pkgfence ssh precheck <name>`** — diagnostic CLI that verifies host reachability, osv-scanner presence (with version regex validation), and discover_paths existence. Operators run this before the first scan of a new tier-1 host.
- **New S4 invariant** — `scripts/scan_remote.py` and `scripts/discover_remote.py` must never retrieve remote file CONTENTS (only paths, hashes, scanner JSON). Enforced via static regex check in `tests/test_s4_no_remote_content_exfil.py`.
- **YAML frontmatter in reports** — every `state/reports/<run-id>.md` now starts with a `---`-delimited block with `run_id`, `timestamp`, `scanner_host`, `pkgfence_version`, `scanner_version`, `exit_code`, `targets_scanned`, `findings_total`, `findings_by_severity` (in severity-rank order: critical, high, medium, low, info, other), `degraded_modes`, `ssh_targets`, `local_roots`. Machine-parseable by AI agents, yq, log aggregators.
- **Publish sinks** — optional `publish:` registry section supports `type: scp` sinks. After writing local artifacts, scan_command pushes `.md`, `.sarif`, and `.jsonl` to `<destination>:<remote_base>/<scanner_host>/<filename>`. Scanner host subdirectory keeps multi-source publishes isolated. Best-effort: failures logged but never change exit code.
- **SSH hardening baked in**: all scp/ssh publish calls use `-o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new` to prevent the "Too many authentication failures" failure mode from ssh-agent fanout.
- **Windows cp1252 fix** — every `subprocess.run` call with `text=True` now pins `encoding="utf-8", errors="replace"`. Prevents latent UnicodeDecodeError on Windows when osv-scanner returns non-ASCII bytes from international packages.
- **node_modules exclusion in remote discovery** — shared `DEFAULT_EXCLUDES` from `scripts.discover` now prunes node_modules, .git, .venv, __pycache__, dist, build, target, vendor, fixtures on the remote too.

### Safety invariants (after Phase 2)

- **S1**: SSH unreachable raises `SSHUnreachableError`, never silent local fallback (Phase 1)
- **S2**: No package-manager install commands anywhere in scripts (Phase 1)
- **S3**: SSH command allowlist — only `find`, `cat`, `sha256sum`, `ls`, `stat`, `osv-scanner`, `trivy`, `zizmor` may run remotely (Phase 1)
- **S4**: No remote file content exfiltration — `scan_remote.py` and `discover_remote.py` only transmit paths, hashes, and scanner JSON. Never `scp`/`rsync`/`sftp`/`dd`/`cat <manifest>` (NEW in Phase 2)

### Bugs fixed during Phase 2 dogfood

- **Tier-2 dogfood revealed 6 bugs** (all fixed in commit `f6bfc56`):
  - `ssh_precheck` false-positive when osv-scanner not in remote PATH (no version regex validation)
  - Remote discovery didn't exclude `node_modules` → nested yarn.locks polluted reports
  - `ssh-mode.md` install docs had wrong URL and wrong location (`~/.local/bin` not in non-interactive PATH)
  - Audit log `manifests_scanned` counted only local manifests
  - MSYS Git Bash auto-converts `/opt` → `C:/Program Files/Git/opt`; `add-ssh` now validates POSIX paths
  - `pyproject.toml` recognized by discovery but osv-scanner has no extractor → removed from `MANIFEST_ECOSYSTEM`
- **Tier-1 dogfood revealed 2 more bugs** (all fixed):
  - SSH non-default port support (`port: 2222` field) — commit `3351e7e`
  - Windows cp1252 encoding crash on UTF-8 osv-scanner output — commit `d03faae`

### Architectural enhancements

- `_scan_error_finding` helper in `scan_remote.py` (DRY)
- `_build_frontmatter` with block-style YAML in severity-rank order
- Shell-safe mkdir in publish (`shlex.quote` + sanitized `scanner_host`)
- `target_runners` dict in `scan_command.run_scan` — one `SSHRunner` per target, reused for L1b + L2b

### New test files

- `tests/test_registry_cli_ssh.py` — add-ssh, remove-ssh, list-with-ssh
- `tests/test_ssh_runner_extensions.py` — key_file, use_sudo, port, utf-8 decoding
- `tests/test_discover_remote.py` — find+sha256sum, SCAN_ERROR wrapper, node_modules exclusion
- `tests/test_scan_remote.py` — remote osv-scanner orchestration, SCAN_ERROR isolation
- `tests/test_s4_no_remote_content_exfil.py` — S4 invariant enforcement
- `tests/test_scan_command_ssh.py` — end-to-end scan_command + ssh + publish
- `tests/test_ssh_precheck.py` — precheck CLI
- `tests/test_publish.py` — publish schema + scp sink (13 unit tests)

### Test count

179 tests passing (was 105 at end of Phase 1), built strictly via TDD.

### Scanner + deps used during dogfood

- pkgfence v0.2.0-dev → v0.2.0
- osv-scanner v2.3.3 (Linux SHA256 `777b4bb7ddd10bdcc8a1aa398d37d05e91e866e7586f9cff3fca2f72b8153033`)
- Python 3.11+ (Windows), Python 3.14.3 (dev machine)
- Pinned runtime deps: httpx[http2]==0.27.2, ruamel.yaml==0.18.6, jsonschema==4.23.0, portalocker==2.10.1

### Documentation

- `references/workflows/ssh-mode.md` — SSH mode workflow including ACL Pattern A1, sudo Pattern A2, manual osv-scanner install, publish configuration

### Production validation

- Tier-2: two Proxmox LXCs — 4 manifests, 69 findings, 0 critical
- Tier-1: two production Plesk hosts — 129 manifests, 1326 findings, **1 real critical** (`MAL-2023-462 fsevents@1.2.4` in a legacy Pydio install)
- Reports auto-published over the configured SCP sink after every scan

### Not yet supported (Phase 3+)

- GitHub mode (api / clone) — originally planned for Phase 2, deferred to v0.3.0
- Auto-bootstrap (`pkgfence ssh bootstrap <name>`) — manual install still required for now
- EPSS, GHSA, deps.dev, OpenSSF Scorecard enrichment (Phase 3)
- Behavioral heuristics (Phase 3)
- Watch mode, audit mode (Phase 4)
- Layer 5 fix-recommendation pipeline (Phase 4) — stand-in hand-written for the mars finding
- EOL software detection (Phase 5)
- "is the package actually installed?" + OS correlation checks (Phase 3+ enhancements)

---

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

Further phases (4–5) are planned.

---

## v0.0.1 — 2026-04-06 (Planning artifacts)

Initial commit of design, plan, and 3 rounds of research. No implementation yet.

See commit `036c355`.

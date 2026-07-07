# pkgfence v0.3.0 Code Review — July 2026

**Reviewer:** Toast (polecat agent)
**Date:** 2026-07-07
**Scope:** Full `scripts/` implementation (L1–L4 pipeline + lib helpers), tests, config
**Test environment:** Python 3.13.5, Linux, pytest 9.0.3

---

## No CRITICAL safety-invariant breaks found

All four safety invariants (S1–S4) pass their tests and the enforcement is substantive, not theatre. One HIGH-severity concern exists around the S4a scoped exception (see below).

---

## 1. Strengths

1. **Pipeline architecture is clean and well-ordered.** `scan_command.py:run_scan()` wires L1→L2→L3→L3.5→L4→Output→Publish as a fixed sequence with clear layer boundaries (`scan_command.py:80-353`). Each layer has a local and remote variant, and the ordering decisions inside L4 are documented and load-bearing (issues #10, #11, #15).

2. **Safety invariants are genuinely enforced, not just asserted.**
   - **S1** (`ssh_runner.py:95-108`): `SSHUnreachableError` is raised on rc=255, TimeoutExpired, FileNotFoundError, and OSError. No local-fallback code path exists anywhere.
   - **S2** (`test_safety_invariants.py:54-63`): Static regex scan of all `scripts/**/*.py` for install patterns. No violations.
   - **S3** (`ssh_runner.py:49-63`): `ALLOWED_COMMANDS` frozenset checked before every remote execution. Shell quoting is centralized via `shlex.quote` in `_build_ssh_cmd`. Control character rejection adds defense-in-depth.
   - **S4** (`test_s4_no_remote_content_exfil.py`): Static regex checks on `scan_remote.py` and `discover_remote.py`. Runtime enforcement via S3 allowlist.

3. **Feed cache lifecycle is robust.** `FeedCacheClient` (`feed_cache.py:27-130`) implements validate-before-publish (temp file + `os.replace`), degrade-once semantics, and stale-feed signaling. The per-process tmp name prevents concurrent-run cache poisoning (`feed_cache.py:68-69`). EPSS client adds host allowlist validation for redirect chains (`epss_client.py:37-52`).

4. **SCAN_ERROR isolation works.** A single bad target produces a SCAN_ERROR Finding that flows through L3/L4 unchanged (`scan_local.py:332-353`, `scan_remote.py:18-30`, `discover_remote.py:137-160`). Status records are never deduped, enriched, scored, demoted, or excluded (`types.py:102-106`).

5. **Test discipline.** 341 tests, all passing in 3.09s. 90% line coverage across `scripts/`. Every module has a corresponding test file. Safety invariant tests are non-negotiable.

6. **Dependency injection pattern.** `SSHRunner` is constructed in `scan_command.py` and passed to remote modules — never constructed inside consumers. This makes testing clean and prevents hidden coupling.

7. **Triple-score ranking is well-isolated.** `priority.py` isolates the scoring formula, avoiding import cycles. Weights come from config, not hardcoded. The formula runs as the FINAL enrichment stage, seeing post-override/post-demotion severities.

---

## 2. Issues Found (ranked by severity)

### HIGH

#### H1. S4a symlink escape in EOL remote detection
**File:** `scripts/eol_detect.py:171-181, 278-279`

`eol_detect.py` uses `runner.run(["cat", version_path])` to read remote version files. The path validation in `_is_safe_remote_version_path()` checks that the path is absolute, has no `..` segments, and sits under a configured `discover_paths` root. However, a **symlink** under `discover_paths` can point anywhere on the remote filesystem. The code acknowledges this in comments (`eol_detect.py:199-202`) but does not mitigate it.

**Risk:** A compromised remote host could place a symlink under `discover_paths` pointing to `/etc/shadow` or any other sensitive file. The version-token cap (`_VERSION_RE`, 64 chars max) bounds what can transit, but the `cat` still executes against the symlink target.

**Recommendation:** Add `stat -L` check before `cat` to verify the resolved path is still under `discover_paths`, or accept the residual risk explicitly in the S4a documentation.

#### H2. SARIF emitter hardcoded version "0.1.0"
**File:** `scripts/lib/sarif.py:91`

```python
"version": "0.1.0",
```

The SARIF output claims pkgfence is version 0.1.0 regardless of the actual installed version. This is stale from Phase 1 and misleads downstream SARIF consumers (GitHub Code Scanning, etc.).

**Recommendation:** Use `_get_pkgfence_version()` from `scan_command.py` or pass the version as a parameter.

#### H3. SARIF emitter hardcoded wrong GitHub URL
**File:** `scripts/lib/sarif.py:91`

```python
"informationUri": "https://github.com/ryanm/pkgfence",
```

But `DEVELOPMENT.md:31` references `https://github.com/jimstratus/pkgfence.git`. The SARIF output points to a different (possibly non-existent) repository.

**Recommendation:** Make `informationUri` configurable or derive from a single source of truth.

### MEDIUM

#### M1. Baseline save is NOT atomic
**File:** `scripts/lib/baseline.py:14-18`

```python
def save_baseline(path: Path, baseline: dict[str, Any]) -> None:
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
```

`save_baseline()` uses `write_text()` directly — a crash mid-write leaves a truncated JSON file. This contrasts with `registry.save_registry_atomic()` (`registry.py:51-83`) which correctly uses temp file + `os.replace`. The `load_baseline()` function would then return corrupted data on the next scan.

**Recommendation:** Apply the same temp-file + `os.replace` pattern used in `registry.py`.

#### M2. Audit log claims portalocker but doesn't use it
**File:** `scripts/lib/audit_log.py:14-27`

The module docstring says "atomic audit log writes with portalocker" and `AGENTS.md` claims "portalocker for atomic file writes (audit log, baselines)". But `append_audit_record()` simply opens in append mode without any locking. The per-run file strategy sidesteps the shared-append race, but the documentation is misleading.

**Recommendation:** Either add portalocker or correct the documentation to reflect the per-run file strategy.

#### M3. Discovery file_count cap is shared across all roots
**File:** `scripts/discover.py:50-60`

```python
file_count = 0
for root in roots:
    ...
    for path in _walk_with_depth(root_path, excludes, max_depth):
        file_count += 1
        if file_count > max_files:
            return
```

The `max_files=10000` cap is shared across ALL roots. If the first root has 9999 files, the second root gets only 1 file scanned before the generator returns. This is a silent truncation — no warning, no log message.

**Recommendation:** Either make the cap per-root, or log a warning when the cap is hit.

#### M4. Mid-file import in scan_local.py
**File:** `scripts/scan_local.py:112`

```python
import json as _json
```

This mid-file import is inconsistent with the top-level `import json` convention used elsewhere. The `_json` alias appears to avoid a name collision, but there is no collision — `json` is not used as a variable name anywhere in the module.

**Recommendation:** Move to top-level imports.

#### M5. OSVClient cache write is not atomic
**File:** `scripts/lib/osv_client.py:91-101`

`_cache_set()` uses `path.write_text()` directly. A concurrent run could read a partial write. Unlike `FeedCacheClient` which uses temp-file + `os.replace`, the OSV client has no atomicity guarantee.

**Recommendation:** Apply temp-file + `os.replace` pattern, or document that OSV cache corruption is acceptable (it falls through to live fetch on parse failure).

#### M6. Inconsistent logger usage in eol_detect.py
**File:** `scripts/eol_detect.py:17`

```python
log = logging.getLogger(__name__)
```

Every other module uses `from scripts.lib.logger import get_logger`. `eol_detect.py` bypasses the centralized logging factory, meaning its log output won't go to the `state/logs/pkgfence.log` file handler.

**Recommendation:** Use `get_logger(__name__)` for consistency.

#### M7. `load_defaults()` is cached for process lifetime
**File:** `scripts/lib/config.py:35-36`

```python
@lru_cache(maxsize=1)
def load_defaults() -> dict[str, Any]:
```

The `@lru_cache` means defaults are loaded once per process and never refreshed. For the current CLI usage (one scan per process), this is fine. But if pkgfence ever runs as a long-lived daemon (watch mode), config changes would be invisible.

**Recommendation:** Document this as a known limitation, or add a `clear_cache()` hook for future watch mode.

#### M8. Publish SSH calls are NOT covered by S3 allowlist
**File:** `scripts/publish.py:153-161`

`publish.py` builds its own `ssh` and `scp` commands outside `SSHRunner`. This means publish's remote commands (`mkdir -p`) are NOT subject to the S3 allowlist check. This is by design (publish has its own key management and runs `mkdir`, which is not in the allowlist), but it means the S3 invariant documentation is incomplete — it should note that publish is an exception.

**Recommendation:** Document the publish exception in `SAFETY_INVARIANTS.md`.

### LOW

#### L1. No lint or static analysis configured
README line 240: "Lint: not yet configured (Phase 5)". No ruff, flake8, mypy, or any static analysis tool is configured. For a security scanner, the absence of type checking is notable.

#### L2. CI uses Python 3.11, dev uses 3.14.3
`.github/workflows/test.yml:16` pins Python 3.11. `CHANGELOG.md:116` references Python 3.14.3 for dev. The gap between CI and dev environments could mask version-specific issues.

#### L3. `_FORBIDDEN_ARG_CHARS` doesn't include tab
**File:** `scripts/lib/ssh_runner.py:47`

```python
_FORBIDDEN_ARG_CHARS = ("\x00", "\n", "\r")
```

Tab (`\t`) could also corrupt line-oriented output parsing but is not rejected.

#### L4. `discover_manifests_full` doesn't pass `max_files` to project walk
**File:** `scripts/discover.py:120-133`

The project walk at line 125 calls `_walk_with_depth` without a `max_files` counter. The file-count cap from `discover_manifests()` is not shared with the project walk, meaning projects can yield unlimited manifests beyond the cap.

---

## 3. Test Count Discrepancy

| Source | Claim | Actual |
|--------|-------|--------|
| README.md:43 | "341 tests passing" | **341** ✓ |
| README.md:238 | "341 tests" | **341** ✓ |
| AGENTS.md | "341 pytest tests" | **341** ✓ |
| CHANGELOG.md:27 (v0.3.0) | "270 → 270 tests passing (Phase 3a added ~32 new tests across 3 new test files)" | **341** ✗ |
| tests/AGENTS.md | "179 pytest tests" | **341** ✗ |

The CHANGELOG v0.3.0 entry is internally contradictory: it claims "270 → 270" while also saying "~32 new tests" were added. The actual count is 341. The `tests/AGENTS.md` is stale at 179 (the Phase 2 count from `CHANGELOG.md:110`).

**Actual test run:**
```
341 passed in 3.09s
```

---

## 4. Coverage Summary

```
Total: 1966 statements, 194 missed, 90% coverage
```

| Module | Coverage | Notes |
|--------|----------|-------|
| `scripts/lib/types.py` | 100% | Core data types fully covered |
| `scripts/lib/priority.py` | 100% | Triple-score fully covered |
| `scripts/lib/frontmatter.py` | 100% | Round-trip fully covered |
| `scripts/enrich_epss.py` | 100% | L3.5 fully covered |
| `scripts/enrich_threats.py` | 100% | KEV enrichment fully covered |
| `scripts/lib/ssh_runner.py` | 98% | Only line 53 (empty command ValueError) uncovered |
| `scripts/scan_remote.py` | 98% | Only line 102 (malformed batch output) uncovered |
| `scripts/triage.py` | 98% | Only line 129 (exclusion category match) uncovered |
| `scripts/notify.py` | 98% | Two lines uncovered (report path missing, main guard) |
| `scripts/lib/registry.py` | 82% | Error paths and atomic-write failure uncovered |
| `scripts/scan_local.py` | 82% | OSV API fallback path and several error branches uncovered |
| `scripts/scan_command.py` | 85% | CLI main() and error paths uncovered |
| `scripts/registry_cli.py` | 81% | Many CLI subcommand error paths uncovered |
| `scripts/lib/exceptions.py` | 73% | Several parsing branches uncovered |

---

## 5. Doc/Code Drift

| # | Document | Claim | Actual | Severity |
|---|----------|-------|--------|----------|
| D1 | `AGENTS.md` header | "pytest 8.3.4" | `pyproject.toml:17` pins `pytest==9.0.3` | Medium |
| D2 | `AGENTS.md` header | "Updated: 2026-04-10" | Last commit: 2026-06-26 | Low |
| D3 | `tests/AGENTS.md` | "179 pytest tests" | 341 tests | Medium |
| D4 | `tests/AGENTS.md` | "pytest 8.3.4" | `pytest==9.0.3` | Medium |
| D5 | `CHANGELOG.md:27` | "270 → 270 tests passing" | 341 tests | Medium |
| D6 | `CHANGELOG.md:197` (v0.1.0) | "Pinned dev deps: pytest==8.3.4" | `pyproject.toml:17` pins `pytest==9.0.3` | Low |
| D7 | `scripts/lib/sarif.py:91` | `"version": "0.1.0"` | pkgfence is v0.3.0 | High |
| D8 | `scripts/lib/sarif.py:91` | `"informationUri": "https://github.com/ryanm/pkgfence"` | `DEVELOPMENT.md:31` references `jimstratus/pkgfence` | High |
| D9 | `scripts/lib/audit_log.py` docstring | "atomic audit log writes with portalocker" | No portalocker used | Medium |
| D10 | `AGENTS.md` Dependencies | "portalocker 2.10.1 — Cross-platform file locking for atomic writes" | Only used in `feed_cache.py`, not in audit_log or baseline | Low |
| D11 | `scripts/enrich_threats.py:6` | "(Phase 2+: epss_score, deps.dev health, GHSA cross-check)" | EPSS is implemented (Phase 3a), comment is stale | Low |

---

## 6. Dependency Hygiene

| Package | Pinned | Current (approx.) | Status |
|---------|--------|-------------------|--------|
| `ruamel.yaml` | 0.18.6 | 0.18.x | OK |
| `httpx[http2]` | 0.27.2 | 0.28.x available | Slightly outdated |
| `jsonschema` | 4.23.0 | 4.23.x | OK |
| `portalocker` | 2.10.1 | 2.10.x | OK |
| `cvss` | 3.4 | 3.x | OK |
| `pytest` | 9.0.3 | 9.x | OK |
| `pytest-cov` | 5.0.0 | 6.x available | Outdated |
| `pytest-mock` | 3.14.0 | 3.14.x | OK |

`requirements.txt` is pip-compiled and consistent with `pyproject.toml`.

---

## 7. Deferred Work Inventory

All items listed in README "What's deferred (Phase 3b+)" are confirmed genuinely unbuilt:

| Feature | Status | Evidence |
|---------|--------|----------|
| GitHub mode (api/clone) | **Unbuilt** | Registry schema has `github:` section with `account`, `orgs`, `default_mode` fields, but no implementation. `scan_command.py:130` creates empty `"github": []` for adhoc scans. `registry_cli.py:52-54` lists github accounts but has no `add-github` subcommand. |
| Auto-bootstrap | **Unbuilt** | No code references. |
| Watch mode | **Unbuilt** | Only reference is `registry.py:60` comment about "multiple concurrent writers" when watch mode lands. |
| Audit mode | **Unbuilt** | No code references. |
| L5 fix-recommendation | **Unbuilt** | No code references. |
| deps.dev + Scorecard | **Unbuilt** | Only a comment at `scan_command.py:219` ("adding deps.dev later = adding a tuple") and `enrich_threats.py:6` ("Phase 2+: deps.dev health"). The enricher loop architecture is ready for it. |
| Behavioral heuristics | **Unbuilt** | No code references. |
| Reachability tiering | **Unbuilt** | No code references. |
| Meta mode | **Unbuilt** | No code references. |

---

## 8. Recommendations (prioritized)

1. **Fix SARIF version and URL** (H2, H3) — Quick wins. Pass version from `_get_pkgfence_version()` and make `informationUri` configurable or correct it.

2. **Make baseline save atomic** (M1) — Apply the same temp-file + `os.replace` pattern from `registry.py`. This is a crash-safety issue.

3. **Correct test count in CHANGELOG and tests/AGENTS.md** (D3, D5) — Update stale documentation.

4. **Update AGENTS.md pytest version** (D1, D4) — Change "8.3.4" to "9.0.3" throughout.

5. **Add discovery file_count warning** (M3) — Log when the cap is hit so operators know discovery was truncated.

6. **Standardize logger usage** (M6) — Switch `eol_detect.py` to `get_logger(__name__)`.

7. **Document S4a symlink residual risk** (H1) — Either add a `stat -L` check or explicitly accept the risk in `SAFETY_INVARIANTS.md`.

8. **Configure lint** (L1) — Add ruff or equivalent. For a security tool, the absence of static analysis is a gap.

9. **Document publish S3 exception** (M8) — Note in `SAFETY_INVARIANTS.md` that publish builds its own SSH commands outside the allowlist.

10. **Consider adding mypy** (L1) — TypedDicts are defined but never checked by a type checker.

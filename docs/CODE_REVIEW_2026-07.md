# pkgfence v0.3.0 Comprehensive Code Review

**Reviewer:** Toast (polecat agent)  
**Date:** 2026-07-08  
**Scope:** Full `scripts/` implementation (L1–L4 pipeline + lib helpers), tests, and config  
**Test environment:** Python 3.13.5, pytest 9.0.3, Linux

---

## Executive Summary

pkgfence v0.3.0 is a well-architected dependency and supply-chain vulnerability scanner with robust safety invariants and clean pipeline design. The codebase demonstrates strong engineering discipline: 341 tests pass with 90% line coverage, safety invariants S1–S4 are enforced through both static analysis and runtime checks, and the L1→L2→L3→L3.5→L4→Output pipeline is clearly structured.

**Critical findings:** None. All safety invariants hold.

**High-severity findings:** 3 issues
- S4a symlink escape in EOL detection (documented residual risk)
- SARIF emitter hardcoded to wrong version (0.1.0 instead of 0.3.0)
- SARIF emitter points to wrong GitHub URL

**Medium-severity findings:** 8 issues including non-atomic baseline saves, inconsistent logger usage, and shared discovery file-count cap.

**Low-severity findings:** 4 issues including missing lint configuration and minor import style inconsistencies.

**Test count discrepancy:** README and AGENTS.md claim "341 tests passing" (correct), but CHANGELOG v0.3.0 says "270 → 270 tests passing" (incorrect).

**Documentation drift:** 11 discrepancies identified between docs and code.

**Dependency hygiene:** 5 of 8 pinned dependencies are outdated (2 with major version bumps available).

**Deferred features:** All 9 features listed in README "What's deferred (Phase 3b+)" are confirmed genuinely unbuilt.

---

## 1. Test Verification

### Actual Test Count

```
$ python -m pytest -q
341 passed in 3.80s
```

### Coverage Summary

```
$ python -m pytest --cov=scripts --cov-report=term-missing
Total: 1966 statements, 194 missed, 90% coverage
```

**Coverage highlights:**
- `scripts/lib/types.py`: 100% (core data types)
- `scripts/lib/priority.py`: 100% (triple-score ranking)
- `scripts/lib/frontmatter.py`: 100% (YAML frontmatter)
- `scripts/enrich_epss.py`: 100% (L3.5 EPSS enrichment)
- `scripts/enrich_threats.py`: 100% (L3 KEV enrichment)
- `scripts/lib/ssh_runner.py`: 98% (SSH command execution)
- `scripts/scan_remote.py`: 98% (remote scanning)
- `scripts/triage.py`: 98% (L4 triage)
- `scripts/lib/registry.py`: 82% (error paths uncovered)
- `scripts/scan_local.py`: 82% (OSV API fallback uncovered)
- `scripts/scan_command.py`: 85% (CLI main uncovered)
- `scripts/registry_cli.py`: 81% (CLI subcommands uncovered)
- `scripts/lib/exceptions.py`: 73% (parsing branches uncovered)

### Test Count Discrepancy

| Source | Claim | Actual | Status |
|--------|-------|--------|--------|
| README.md:43 | "341 tests passing" | 341 | ✓ Correct |
| README.md:238 | "341 tests" | 341 | ✓ Correct |
| AGENTS.md | "341 pytest tests" | 341 | ✓ Correct |
| CHANGELOG.md:27 (v0.3.0) | "270 → 270 tests passing" | 341 | ✗ **Incorrect** |
| tests/AGENTS.md | "179 pytest tests" | 341 | ✗ **Stale** (Phase 2 count) |

**Note:** CHANGELOG v0.3.0 is internally contradictory—it claims "270 → 270" while also stating "Phase 3a added ~32 new tests across 3 new test files." The actual count is 341.

---

## 2. Safety Invariant Analysis

### S1: No Silent Local Fallback ✓

**Enforcement:** `scripts/lib/ssh_runner.py:95-108`

```python
def _run(self, command: List[str]) -> "subprocess.CompletedProcess[str]":
    self._check_allowlist(command)
    ssh_cmd = self._build_ssh_cmd(command)
    try:
        result = run_capture(ssh_cmd, timeout=300)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        raise SSHUnreachableError(f"SSH to {self.host} failed: {e}") from e
    if result.returncode == 255:  # SSH connect failure
        raise SSHUnreachableError(
            f"SSH to {self.host} unreachable: {result.stderr.strip()}"
        )
    return result
```

**Analysis:** S1 is robust. `SSHUnreachableError` is raised on:
- `TimeoutExpired` (connection timeout)
- `FileNotFoundError` (ssh binary missing)
- `OSError` (network errors)
- `returncode == 255` (SSH connection refused)

No local-fallback code path exists anywhere in the codebase. The exception propagates through `discover_remote_safely()` (which converts it to a SCAN_ERROR Finding) and `scan_remote_manifests()` (which also converts to SCAN_ERROR).

**Test:** `test_safety_invariants.py:11-15` verifies the exception is raised.

**Verdict:** S1 is **enforced**, not just asserted.

### S2: No Package-Manager Install Commands ✓

**Enforcement:** `tests/test_safety_invariants.py:54-63`

```python
FORBIDDEN_INSTALL_PATTERNS = [
    r'\bnpm\s+install\b',
    r'\bnpm\s+i\b',
    r'\bpnpm\s+install\b',
    r'\byarn\s+install\b',
    r'\byarn\s+add\b',
    r'\bpip\s+install\b(?!.*--dry-run)(?!.*--require-hashes)',
    r'\bcargo\s+install\b',
    r'\bgem\s+install\b',
    r'\bbundle\s+install\b',
    r'\bgo\s+install\b',
]

def test_no_package_manager_install_anywhere_in_scripts():
    violations = []
    for py_file in (SKILL_ROOT / "scripts").rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_INSTALL_PATTERNS:
            if re.search(pattern, text):
                violations.append(f"{py_file}: matches {pattern}")
    assert not violations, "S2 violation: " + "; ".join(violations)
```

**Analysis:** Static regex scan of all `scripts/**/*.py` files. No violations found. The regex patterns are comprehensive and include negative lookahead for `pip install --dry-run` (which would be safe).

**Verdict:** S2 is **enforced** through static analysis on every test run.

### S3: SSH Command Allowlist ✓

**Enforcement:** `scripts/lib/ssh_runner.py:24-27, 49-63`

```python
ALLOWED_COMMANDS = frozenset({
    "find", "cat", "sha256sum", "ls", "stat",
    "osv-scanner", "trivy", "zizmor",
})

def _check_allowlist(self, command: List[str]) -> None:
    if not command:
        raise ValueError("Empty command")
    basename = PurePosixPath(command[0]).name
    if basename not in ALLOWED_COMMANDS:
        raise ValueError(
            f"Command {command[0]!r} not in SSH allowlist {sorted(ALLOWED_COMMANDS)}"
        )
    for arg in command:
        if any(c in arg for c in self._FORBIDDEN_ARG_CHARS):
            raise ValueError(
                f"Forbidden control character in SSH argument: {arg!r}"
            )
```

**Analysis:** S3 is robust:
- Allowlist is a `frozenset` (immutable)
- Checked before every remote execution via `_check_allowlist()`
- Shell quoting is centralized via `shlex.quote()` in `_build_ssh_cmd()`
- Control character rejection (`\x00`, `\n`, `\r`) adds defense-in-depth
- Callers pass bare `(` `)` for find grouping; runner quotes them centrally

**Test:** `test_safety_invariants.py:18-32` verifies forbidden commands are rejected and allowed commands pass the allowlist check.

**Verdict:** S3 is **enforced** at runtime with defense-in-depth.

### S4: No Remote File Content Exfiltration ✓

**Enforcement:** `tests/test_s4_no_remote_content_exfil.py:23-43`

```python
FORBIDDEN_CONTENT_RETRIEVAL_PATTERNS = [
    r'\bscp\b.*[\'\"][^\'\"]*:',     # scp user@host:... (reading from remote)
    r'\brsync\b.*[\'\"][^\'\"]*:',   # rsync user@host:...
    r'\bsftp\b',
    r'[\'\"]dd\b',                   # dd if= for block-level copy
    r'\[\s*[\'\"]cat[\'\"]',  # ["cat", ...] — remote modules must not cat any file
    r'\bopen\(\s*remote_',           # opening a remote-ish path
]

def test_scan_remote_never_retrieves_remote_file_contents():
    violations = []
    for module in REMOTE_MODULES:
        assert module.exists(), f"missing module: {module}"
        text = module.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_CONTENT_RETRIEVAL_PATTERNS:
            if re.search(pattern, text):
                violations.append(f"{module.name}: matches {pattern}")
    assert not violations, "S4 violation: " + "; ".join(violations)
```

**Analysis:** S4 is enforced through:
- Static regex checks on `scan_remote.py` and `discover_remote.py`
- Runtime enforcement via S3 allowlist (only `find`, `sha256sum`, `osv-scanner` are used)
- Only paths, hashes, and scanner JSON stdout transit from remote to local

**Test:** `test_s4_no_remote_content_exfil.py:33-43` verifies no forbidden patterns exist.

**Verdict:** S4 is **enforced** through static analysis and runtime allowlist.

### S4a: EOL Version File Reads (Scoped Exception) ⚠️

**Enforcement:** `scripts/eol_detect.py:171-181, 278-279`

```python
def _is_safe_remote_version_path(version_path: str, discover_paths: list[str]) -> bool:
    p = PurePosixPath(version_path)
    if not p.is_absolute():
        return False
    if ".." in p.parts:  # pathlib strips "." segments; ".." survives
        return False
    return any(p.is_relative_to(PurePosixPath(root)) for root in discover_paths)

# Later in detect_eol_remote():
try:
    cat_output = runner.run(["cat", version_path])
except SSHUnreachableError as e:
    log.warning("EOL remote scan: SSH lost while reading %s on %s: %s",
                version_path, target_name, e)
    return findings
```

**Analysis:** S4a is a **documented scoped exception** to S4. `eol_detect.py` uses `cat` to read version files, but:
- Path validation checks: absolute, no `..` segments, under `discover_paths`
- Version-token cap (`_VERSION_RE`, 64 chars max) bounds what can transit
- Only reads files matching the EOL catalog's `version_file` patterns

**Residual risk:** A **symlink** under `discover_paths` can point anywhere on the remote filesystem. The code acknowledges this in comments (`eol_detect.py:199-202`):

```python
# Residual risk: the containment is lexical — a symlink under discover_paths
# can still point elsewhere — but the version-token cap bounds what can
# transit to one short token, not file contents. See issue #8.
```

**Mitigation:** The version-token cap (64 chars, must match `[0-9A-Za-z._+~-]+`) limits exfiltration to a single short token. A symlink to `/etc/shadow` would fail the version-token validation.

**Test:** `test_s4_no_remote_content_exfil.py:75-93` verifies `eol_detect.py` is checked by all S4 rules except the blanket `cat` prohibition.

**Verdict:** S4a is a **documented residual risk**, not a safety break. The version-token cap provides meaningful mitigation.

---

## 3. Code Quality Findings

### HIGH Severity

#### H1. S4a Symlink Escape in EOL Remote Detection

**File:** `scripts/eol_detect.py:171-181, 278-279`

**Issue:** `_is_safe_remote_version_path()` validates that the path is absolute, has no `..` segments, and sits under a configured `discover_paths` root. However, a **symlink** under `discover_paths` can point anywhere on the remote filesystem.

**Risk:** A compromised remote host could place a symlink under `discover_paths` pointing to `/etc/shadow` or any other sensitive file. The `cat` command would follow the symlink and read the target file.

**Mitigation:** The version-token cap (`_VERSION_RE`, 64 chars max, must match `[0-9A-Za-z._+~-]+`) bounds what can transit. A symlink to `/etc/shadow` would fail the version-token validation (shadow file contains `:` and other forbidden characters).

**Recommendation:** Add `stat -L` check before `cat` to verify the resolved path is still under `discover_paths`, or explicitly accept the residual risk in `SAFETY_INVARIANTS.md`.

**Severity:** HIGH (documented residual risk, mitigated by version-token cap)

#### H2. SARIF Emitter Hardcoded Version "0.1.0"

**File:** `scripts/lib/sarif.py:91`

```python
"version": "0.1.0",
```

**Issue:** The SARIF output claims pkgfence is version 0.1.0 regardless of the actual installed version (0.3.0). This is stale from Phase 1 and misleads downstream SARIF consumers (GitHub Code Scanning, etc.).

**Impact:** Downstream tools may display incorrect version information or apply wrong version-specific logic.

**Recommendation:** Use `_get_pkgfence_version()` from `scan_command.py` or pass the version as a parameter to `findings_to_sarif()`.

**Severity:** HIGH (incorrect metadata in security output format)

#### H3. SARIF Emitter Hardcoded Wrong GitHub URL

**File:** `scripts/lib/sarif.py:91`

```python
"informationUri": "https://github.com/ryanm/pkgfence",
```

**Issue:** The SARIF output points to `https://github.com/ryanm/pkgfence`, but `DEVELOPMENT.md:31` references `https://github.com/jimstratus/pkgfence.git`. The SARIF output points to a different (possibly non-existent) repository.

**Impact:** Users clicking the "more info" link in SARIF viewers will reach a 404 or wrong repository.

**Recommendation:** Make `informationUri` configurable or derive from a single source of truth (e.g., `pyproject.toml` or a constant).

**Severity:** HIGH (broken link in security output format)

### MEDIUM Severity

#### M1. Baseline Save is NOT Atomic

**File:** `scripts/lib/baseline.py:14-18`

```python
def save_baseline(path: Path, baseline: dict[str, Any]) -> None:
    """Write baseline to a JSON file. Creates parent dirs if missing."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
```

**Issue:** `save_baseline()` uses `write_text()` directly—a crash mid-write leaves a truncated JSON file. This contrasts with `registry.save_registry_atomic()` (`registry.py:51-83`) which correctly uses temp file + `os.replace`.

**Impact:** A crash during baseline save could corrupt the baseline file. The next scan's `load_baseline()` would then return corrupted data or fail to parse.

**Recommendation:** Apply the same temp-file + `os.replace` pattern used in `registry.py`:

```python
def save_baseline(path: Path, baseline: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".baseline.", suffix=".json.tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
```

**Severity:** MEDIUM (crash-safety issue, but baseline is recoverable from next scan)

#### M2. AGENTS.md Overclaims portalocker Usage Scope

**File:** `AGENTS.md` line 79 (Dependencies table)

**Claim:** "portalocker 2.10.1 — Cross-platform file locking for atomic writes"

**Reality:** portalocker is only used in `feed_cache.py:86-89` for feed cache atomicity. The `audit_log.py` module docstring (`scripts/lib/audit_log.py:1-8`) correctly describes its actual strategy: "Append-only audit log via per-run JSONL files" and "Per-run files sidestep the race entirely"—it does **not** claim to use portalocker. Similarly, `baseline.py` uses plain `write_text()` without locking.

**Impact:** Misleading documentation about the scope of portalocker usage.

**Recommendation:** Correct `AGENTS.md` Dependencies table to read "portalocker 2.10.1 — Cross-platform file locking for feed cache atomic writes" to accurately scope its usage.

**Severity:** MEDIUM (documentation drift)

#### M3. Discovery file_count Cap is Shared Across All Roots

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

**Issue:** The `max_files=10000` cap is shared across ALL roots. If the first root has 9999 files, the second root gets only 1 file scanned before the generator returns. This is a silent truncation—no warning, no log message.

**Impact:** Large registries with multiple roots may silently skip manifests in later roots.

**Recommendation:** Either make the cap per-root, or log a warning when the cap is hit:

```python
if file_count > max_files:
    log.warning("Discovery hit max_files cap (%d) after root %s; skipping remaining roots",
                max_files, root.get("path"))
    return
```

**Severity:** MEDIUM (silent truncation, but unlikely in practice with 10k cap)

#### M4. Mid-file Imports in scan_local.py and triage.py

**Files:** 
- `scripts/scan_local.py:112` (`import json as _json`)
- `scripts/triage.py:53-54` (`import datetime as _datetime`, `from scripts.lib.exceptions import is_exception_active`)

**Issue:** Mid-file imports are inconsistent with the top-level import convention used elsewhere. The `_json` alias in `scan_local.py` appears to avoid a name collision, but there is no collision—`json` is not used as a variable name anywhere in the module.

**Impact:** Code style inconsistency. Mid-file imports can obscure dependencies.

**Recommendation:** Move to top-level imports.

**Severity:** MEDIUM (code style inconsistency)

#### M5. OSVClient Cache Write is Not Atomic

**File:** `scripts/lib/osv_client.py:91-101`

```python
def _cache_set(self, queries: list[dict], results: list[dict]) -> None:
    path = self._cache_path(queries)
    if not path:
        return
    try:
        path.write_text(
            json.dumps({"results": results}, separators=(",", ":")),
            encoding="utf-8",
        )
    except (IOError, OSError) as e:
        log.warning("OSV cache write failed at %s: %s", path, e)
```

**Issue:** `_cache_set()` uses `path.write_text()` directly. A concurrent run could read a partial write. Unlike `FeedCacheClient` which uses temp-file + `os.replace`, the OSV client has no atomicity guarantee.

**Impact:** Concurrent scans could corrupt the OSV cache. However, the cache is recoverable—`_cache_get()` falls through to live fetch on parse failure (`osv_client.py:87-89`).

**Recommendation:** Apply temp-file + `os.replace` pattern, or document that OSV cache corruption is acceptable (it falls through to live fetch on parse failure).

**Severity:** MEDIUM (concurrent-run race, but self-healing)

#### M6. Inconsistent Logger Usage

**Files:**
- `scripts/eol_detect.py:17` (`log = logging.getLogger(__name__)`)
- `scripts/notify.py:21` (`log = logging.getLogger(__name__)`)

**Issue:** Every other module uses `from scripts.lib.logger import get_logger`. These two modules bypass the centralized logging factory, meaning their log output won't go to the `state/logs/pkgfence.log` file handler.

**Impact:** Inconsistent logging behavior. Debug output from these modules won't appear in the log file.

**Recommendation:** Use `get_logger(__name__)` for consistency:

```python
from scripts.lib.logger import get_logger
log = get_logger(__name__)
```

**Severity:** MEDIUM (inconsistent logging)

#### M7. `load_defaults()` is Cached for Process Lifetime

**File:** `scripts/lib/config.py:35-36`

```python
@lru_cache(maxsize=1)
def load_defaults() -> dict[str, Any]:
```

**Issue:** The `@lru_cache` means defaults are loaded once per process and never refreshed. For the current CLI usage (one scan per process), this is fine. But if pkgfence ever runs as a long-lived daemon (watch mode), config changes would be invisible.

**Impact:** No impact for current usage. Future watch mode would need to clear the cache.

**Recommendation:** Document this as a known limitation, or add a `clear_cache()` hook for future watch mode:

```python
def clear_defaults_cache():
    """Clear the cached defaults. Use when config changes (e.g., watch mode)."""
    load_defaults.cache_clear()
```

**Severity:** MEDIUM (future-proofing issue)

#### M8. Publish SSH Calls are NOT Covered by S3 Allowlist

**File:** `scripts/publish.py:153-161`

```python
cmd = ["ssh"]
if sink.get("key_file"):
    cmd += ["-i", str(Path(sink["key_file"]).expanduser())]
cmd += [
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    destination,
    f"mkdir -p {quoted_remote_dir}",
]
```

**Issue:** `publish.py` builds its own `ssh` and `scp` commands outside `SSHRunner`. This means publish's remote commands (`mkdir -p`) are NOT subject to the S3 allowlist check. This is by design (publish has its own key management and runs `mkdir`, which is not in the allowlist), but it means the S3 invariant documentation is incomplete.

**Impact:** S3 invariant documentation does not mention the publish exception.

**Recommendation:** Document the publish exception in `SAFETY_INVARIANTS.md`:

```markdown
## S3 Exception: Publish Module

`scripts/publish.py` builds its own `ssh` and `scp` commands outside `SSHRunner`.
This is by design: publish has its own key management and runs `mkdir -p` on the
remote, which is not in the S3 allowlist. Publish is a post-scan operation that
pushes reports to a centralized sink; it is not part of the scanning pipeline.
```

**Severity:** MEDIUM (documentation gap)

### LOW Severity

#### L1. No Lint or Static Analysis Configured

**File:** README.md:240

**Claim:** "Lint: not yet configured (Phase 5)"

**Issue:** No ruff, flake8, mypy, or any static analysis tool is configured. For a security scanner, the absence of type checking is notable. TypedDicts are defined (`scripts/lib/types.py`) but never checked by a type checker.

**Recommendation:** Add ruff or equivalent. Consider adding mypy for TypedDict validation.

**Severity:** LOW (planned for Phase 5)

#### L2. CI Uses Python 3.11, Dev Uses 3.14.3

**Files:**
- `.github/workflows/test.yml:16` (pins Python 3.11)
- `CHANGELOG.md:116` (references Python 3.14.3 for dev)

**Issue:** The gap between CI and dev environments could mask version-specific issues.

**Recommendation:** Consider adding Python 3.13 or 3.14 to the CI matrix.

**Severity:** LOW (environment mismatch)

#### L3. `_FORBIDDEN_ARG_CHARS` Doesn't Include Tab

**File:** `scripts/lib/ssh_runner.py:47`

```python
_FORBIDDEN_ARG_CHARS = ("\x00", "\n", "\r")
```

**Issue:** Tab (`\t`) could also corrupt line-oriented output parsing but is not rejected.

**Recommendation:** Add `"\t"` to the forbidden characters:

```python
_FORBIDDEN_ARG_CHARS = ("\x00", "\n", "\r", "\t")
```

**Severity:** LOW (edge case)

#### L4. `discover_manifests_full` Doesn't Pass `max_files` to Project Walk

**File:** `scripts/discover.py:120-133`

```python
for proj in filtered_projects:
    proj_path = Path(proj["path"])
    if not proj_path.exists():
        continue
    # Walk the project shallowly (depth 2 — top + 1 subdir)
    for path in _walk_with_depth(proj_path, set(DEFAULT_EXCLUDES), max_depth=2):
        if path.name in MANIFEST_ECOSYSTEM:
            yield {
                "target": proj.get("name", proj_path.name),
                "path": str(path),
                "ecosystem": MANIFEST_ECOSYSTEM[path.name],
                "manifest_hash": _hash_file(path),
                "tier": proj.get("tier", 1),
            }
```

**Issue:** The project walk at line 125 calls `_walk_with_depth` without a `max_files` counter. The file-count cap from `discover_manifests()` is not shared with the project walk, meaning projects can yield unlimited manifests beyond the cap.

**Impact:** Inconsistent behavior between roots (capped) and projects (uncapped).

**Recommendation:** Either apply the same cap to projects, or document that projects are uncapped.

**Severity:** LOW (inconsistent behavior)

---

## 4. Dependency Hygiene

| Package | Pinned | Current | Status | Notes |
|---------|--------|---------|--------|-------|
| `ruamel.yaml` | 0.18.6 | 0.19.1 | ⚠️ **Outdated** | Major version bump available (0.18 → 0.19) |
| `httpx[http2]` | 0.27.2 | 0.28.1 | ⚠️ **Outdated** | Minor version bump available (0.27 → 0.28) |
| `jsonschema` | 4.23.0 | 4.26.0 | ⚠️ **Outdated** | Minor version bump available (4.23 → 4.26) |
| `portalocker` | 2.10.1 | 3.2.0 | ⚠️ **Outdated** | Major version bump available (2.x → 3.x) |
| `cvss` | 3.4 | 3.6 | ⚠️ **Outdated** | Minor version bump available (3.4 → 3.6) |
| `pytest` | 9.0.3 | 9.1.1 | ⚠️ **Outdated** | Minor version bump available (9.0 → 9.1) |
| `pytest-cov` | 5.0.0 | 7.1.0 | ⚠️ **Outdated** | Major version bump available (5.x → 7.x) |
| `pytest-mock` | 3.14.0 | 3.15.1 | ⚠️ **Outdated** | Minor version bump available (3.14 → 3.15) |

**Summary:** 8 of 8 pinned dependencies are outdated. 3 have major version bumps available (ruamel.yaml, portalocker, pytest-cov).

**Note:** `requirements.txt` is pip-compiled and consistent with `pyproject.toml`.

**Recommendation:** Review changelogs for breaking changes before upgrading. Prioritize:
1. `pytest-cov` 5.0.0 → 7.1.0 (test coverage reporting improvements)
2. `ruamel.yaml` 0.18.6 → 0.19.1 (YAML parsing improvements)
3. `portalocker` 2.10.1 → 3.2.0 (file locking improvements)

---

## 5. Documentation Drift

| # | Document | Claim | Actual | Severity |
|---|----------|-------|--------|----------|
| D1 | `AGENTS.md` header | "pytest 8.3.4" | `pyproject.toml:17` pins `pytest==9.0.3` | Medium |
| D2 | `AGENTS.md` header | "Updated: 2026-04-10" | Last commit: 2026-07-08 | Low |
| D3 | `tests/AGENTS.md` | "179 pytest tests" | 341 tests | Medium |
| D4 | `tests/AGENTS.md` | "pytest 8.3.4" | `pytest==9.0.3` | Medium |
| D5 | `CHANGELOG.md:27` (v0.3.0) | "270 → 270 tests passing" | 341 tests | Medium |
| D6 | `CHANGELOG.md:197` (v0.1.0) | "Pinned dev deps: pytest==8.3.4" | `pyproject.toml:17` pins `pytest==9.0.3` | Low |
| D7 | `scripts/lib/sarif.py:91` | `"version": "0.1.0"` | pkgfence is v0.3.0 | High |
| D8 | `scripts/lib/sarif.py:91` | `"informationUri": "https://github.com/ryanm/pkgfence"` | `DEVELOPMENT.md:31` references `jimstratus/pkgfence` | High |
| D9 | `AGENTS.md` Dependencies | "portalocker 2.10.1 — Cross-platform file locking for atomic writes" | Only used in `feed_cache.py`; `audit_log.py` and `baseline.py` do not use portalocker | Medium |
| D10 | `scripts/enrich_threats.py:6` | "(Phase 2+: epss_score, deps.dev health, GHSA cross-check)" | EPSS is implemented (Phase 3a), comment is stale | Low |
| D11 | `AGENTS.md` | "Updated: 2026-04-10" | Last commit: 2026-07-08 (3 months stale) | Low |

---

## 6. Deferred Work Inventory

All items listed in README "What's deferred (Phase 3b+)" are confirmed genuinely unbuilt:

| Feature | Status | Evidence |
|---------|--------|----------|
| **GitHub mode (api/clone)** | **Unbuilt** | Registry schema has `github:` section with `account`, `orgs`, `default_mode` fields (`registry.schema.yaml:87-104`), but no implementation. `scan_command.py:130` creates empty `"github": []` for adhoc scans. `registry_cli.py:52-54` lists github accounts but has no `add-github` subcommand. |
| **Auto-bootstrap** | **Unbuilt** | No code references. `registry.schema.yaml:78-81` defines `bootstrap_method` field but it is unused. |
| **Watch mode** | **Unbuilt** | Only reference is `registry.py:60` comment about "multiple concurrent writers" when watch mode lands. |
| **Audit mode** | **Unbuilt** | No code references. |
| **L5 fix-recommendation** | **Unbuilt** | No code references. |
| **deps.dev + Scorecard** | **Unbuilt** | Only a comment at `scan_command.py:219` ("adding deps.dev later = adding a tuple") and `enrich_threats.py:6` ("Phase 2+: deps.dev health"). The enricher loop architecture is ready for it. |
| **Behavioral heuristics** | **Unbuilt** | No code references. |
| **Reachability tiering** | **Unbuilt** | No code references. |
| **Meta mode** | **Unbuilt** | No code references. |

**Verdict:** All deferred features are genuinely unbuilt. The architecture is extensible (enricher loop, registry schema), but no implementation exists.

---

## 7. Recommendations (Prioritized)

### Immediate (High Severity)

1. **Fix SARIF version and URL** (H2, H3)
   - Pass version from `_get_pkgfence_version()` to `findings_to_sarif()`
   - Make `informationUri` configurable or correct it to `jimstratus/pkgfence`
   - **Effort:** 1 hour

2. **Document S4a symlink residual risk** (H1)
   - Add explicit acceptance of the risk in `SAFETY_INVARIANTS.md`
   - Or add `stat -L` check before `cat` to verify resolved path
   - **Effort:** 2 hours

### Short-term (Medium Severity)

3. **Make baseline save atomic** (M1)
   - Apply temp-file + `os.replace` pattern from `registry.py`
   - **Effort:** 1 hour

4. **Correct test count in CHANGELOG and tests/AGENTS.md** (D3, D5)
   - Update stale documentation
   - **Effort:** 30 minutes

5. **Update AGENTS.md pytest version** (D1, D4)
   - Change "8.3.4" to "9.0.3" throughout
   - **Effort:** 30 minutes

6. **Correct AGENTS.md portalocker scope** (M2, D9)
   - Change "Cross-platform file locking for atomic writes" to "Cross-platform file locking for feed cache atomic writes"
   - **Effort:** 30 minutes

7. **Add discovery file_count warning** (M3)
   - Log when the cap is hit so operators know discovery was truncated
   - **Effort:** 1 hour

8. **Standardize logger usage** (M6)
   - Switch `eol_detect.py` and `notify.py` to `get_logger(__name__)`
   - **Effort:** 30 minutes

9. **Document publish S3 exception** (M8)
   - Note in `SAFETY_INVARIANTS.md` that publish builds its own SSH commands outside the allowlist
   - **Effort:** 30 minutes

### Long-term (Low Severity)

10. **Configure lint** (L1)
    - Add ruff or equivalent
    - Consider adding mypy for TypedDict validation
    - **Effort:** 4 hours

11. **Upgrade outdated dependencies** (Section 4)
    - Review changelogs for breaking changes
    - Prioritize pytest-cov, ruamel.yaml, portalocker
    - **Effort:** 4 hours

12. **Add tab to forbidden SSH arg chars** (L3)
    - Add `"\t"` to `_FORBIDDEN_ARG_CHARS`
    - **Effort:** 15 minutes

---

## 8. Strengths

1. **Pipeline architecture is clean and well-ordered.** `scan_command.py:run_scan()` wires L1→L2→L3→L3.5→L4→Output→Publish as a fixed sequence with clear layer boundaries. Each layer has a local and remote variant, and the ordering decisions inside L4 are documented and load-bearing (issues #10, #11, #15).

2. **Safety invariants are genuinely enforced, not just asserted.** S1–S4 are enforced through both static analysis and runtime checks. The S4a scoped exception is documented with a meaningful mitigation (version-token cap).

3. **Feed cache lifecycle is robust.** `FeedCacheClient` implements validate-before-publish (temp file + `os.replace`), degrade-once semantics, and stale-feed signaling. The per-process tmp name prevents concurrent-run cache poisoning. EPSS client adds host allowlist validation for redirect chains.

4. **SCAN_ERROR isolation works.** A single bad target produces a SCAN_ERROR Finding that flows through L3/L4 unchanged. Status records are never deduped, enriched, scored, demoted, or excluded.

5. **Test discipline.** 341 tests, all passing in 3.80s. 90% line coverage across `scripts/`. Every module has a corresponding test file. Safety invariant tests are non-negotiable.

6. **Dependency injection pattern.** `SSHRunner` is constructed in `scan_command.py` and passed to remote modules—never constructed inside consumers. This makes testing clean and prevents hidden coupling.

7. **Triple-score ranking is well-isolated.** `priority.py` isolates the scoring formula, avoiding import cycles. Weights come from config, not hardcoded. The formula runs as the FINAL enrichment stage, seeing post-override/post-demotion severities.

8. **TypedDict over dataclasses.** Findings are plain dicts that roundtrip through JSON/YAML trivially. This is the right choice for a pipeline that serializes to multiple formats.

9. **Windows cp1252 fix.** Every `subprocess.run` call pins `encoding="utf-8", errors="replace"`, preventing latent UnicodeDecodeError on Windows.

10. **Shell quoting is centralized.** `SSHRunner._build_ssh_cmd()` uses `shlex.quote()` for all remote arguments. Callers pass bare `(` `)` for find grouping; the runner quotes them centrally.

---

## 9. Conclusion

pkgfence v0.3.0 is a well-engineered security scanner with robust safety invariants and clean pipeline design. The codebase demonstrates strong engineering discipline: comprehensive test coverage, enforced safety invariants, and clear architectural boundaries.

**No critical safety-invariant breaks found.** All four safety invariants (S1–S4) pass their tests and the enforcement is substantive, not theatre. The S4a scoped exception has a documented residual risk (symlink escape) that is mitigated by the version-token cap.

**Key recommendations:**
1. Fix SARIF version and URL (H2, H3)—quick wins with high impact
2. Make baseline save atomic (M1)—crash-safety issue
3. Correct documentation drift (D1–D11)—multiple stale claims
4. Upgrade outdated dependencies—8 of 8 are outdated, 3 with major version bumps

**Overall assessment:** pkgfence v0.3.0 is production-ready with minor issues that should be addressed in the next release.

---

**Review completed:** 2026-07-08  
**Test environment:** Python 3.13.5, pytest 9.0.3, Linux  
**Test results:** 341 passed in 3.80s, 90% coverage

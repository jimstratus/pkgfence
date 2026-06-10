# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# Install (editable, with dev deps) — use the venv
.venv/Scripts/python.exe -m pip install -e ".[dev]"

# Run all tests (179 tests)
.venv/Scripts/python.exe -m pytest -v --strict-markers

# Run a single test file
.venv/Scripts/python.exe -m pytest tests/test_scan_command.py -v

# Run a single test function
.venv/Scripts/python.exe -m pytest tests/test_safety_invariants.py::test_no_silent_local_fallback_when_ssh_unreachable -v

# Safety invariant tests specifically (non-negotiable — must always pass)
.venv/Scripts/python.exe -m pytest tests/test_safety_invariants.py tests/test_s4_no_remote_content_exfil.py -v

# Lint
.venv/Scripts/python.exe -m ruff check scripts/ tests/

# Run pkgfence scan (CLI entry point)
.venv/Scripts/python.exe -m scripts.scan_command --registry state/registry.yaml --state state
```

## Architecture

pkgfence is a 4-layer pipeline wired together in `scripts/scan_command.py`:

```
L1 Discovery → L2 Scanner → L3 Enrichment → L4 Triage → Output → Publish
```

Each layer has a local and remote variant:
- **L1:** `discover.py` (local) / `discover_remote.py` (SSH)
- **L2:** `scan_local.py` (local) / `scan_remote.py` (SSH)
- **L3:** `enrich_threats.py` — CISA KEV correlation
- **L4:** `triage.py` — dedup, MAL-* override, exceptions, exclusions, severity sort

`scan_command.py:run_scan()` orchestrates everything: loads registry, runs L1-L4, writes markdown+SARIF+JSONL output, saves baseline, publishes via SCP sink.

**Core data type:** `Finding` TypedDict in `scripts/lib/types.py` flows through every stage. Use TypedDicts (not dataclasses) — they roundtrip through JSON/YAML trivially.

**Remote scanning (Pattern B):** `find` + `sha256sum` + `osv-scanner` run ON the remote host via SSH. Only paths, hashes, and scanner JSON transit back. Source code never leaves the remote.

**Dependency injection:** `SSHRunner` is instantiated once per target in `scan_command.py` and passed into remote modules. Never construct it inside the modules.

**SCAN_ERROR records flow through, never block.** One bad target/manifest produces a SCAN_ERROR Finding that passes through L3/L4 unchanged and appears in the report.

## Safety Invariants (load-bearing)

If any safety test fails, the tool is broken and must NOT be used.

| # | Rule | Enforcement |
|---|------|-------------|
| S1 | SSH unreachable → `SSHUnreachableError`, never silent local fallback | `ssh_runner.py` + `test_safety_invariants.py` |
| S2 | No `npm install` / `pip install` / any package-manager install in scripts | Static regex over `scripts/**/*.py` |
| S3 | SSH commands limited to: `find, cat, sha256sum, ls, stat, osv-scanner, trivy, zizmor` | `ALLOWED_COMMANDS` frozenset in `ssh_runner.py` |
| S4 | No remote file content exfiltration (no scp/rsync/cat reads of manifests) | Static regex in `test_s4_no_remote_content_exfil.py` |

## Critical Gotchas

**Windows subprocess encoding:** Always use `encoding="utf-8", errors="replace"` on every `subprocess.run` call. Without this, Windows defaults to cp1252 and crashes on non-ASCII scanner output.

**MSYS2 path mangling:** When passing POSIX paths to argparse from Git Bash, prefix with `MSYS_NO_PATHCONV=1`. Otherwise `/opt` silently becomes `C:/Program Files/Git/opt`.

**SSH agent fanout:** Always use `-o IdentitiesOnly=yes` when specifying `-i <keyfile>`, otherwise ssh-agent sends all keys first and hits MaxAuthTries.

**POSIX ACL mask trap on Plesk hosts:** When setting default ACLs for scanner read access, ALWAYS include `mask::rwx` — e.g., `setfacl -R -d -m u:scanuser:rX,mask::rwx /var/www`. Without it, the default mask recomputes to `r-x`, stripping group write from PHP-FPM sockets and breaking all websites. See `references/workflows/ssh-mode.md` Pattern A1.

**Remote shell escaping:** `SSHRunner` shell-quotes every argument centrally
(`shlex.quote`) before it reaches the remote login shell — callers must NOT
pre-quote or pre-escape. Pass find's grouping operators as bare `"("` / `")"`.

**YAML round-trip:** Use `YAML(typ="rt")` when dict insertion order matters (frontmatter, registry). Never use `typ="safe"` — it sorts keys alphabetically.

## Testing Conventions

- **One test file per source module:** `test_<module>.py`
- **All imports at module level** — never inline imports inside test functions
- **Mock subprocess as `patch("scripts.lib.proc.subprocess.run")`** — all modules route through `lib/proc.run_capture`
- **Use `tmp_state` and `tmp_registry` fixtures** from `conftest.py` for isolation
- **Remote module tests:** inject `MagicMock` SSHRunners via function params, don't patch globally

## Shared Constants

`DEFAULT_EXCLUDES` and `MANIFEST_ECOSYSTEM` live in `scripts/discover.py` and are imported by `scripts/discover_remote.py`. Never duplicate them — single source of truth.

## State Directory

`state/` is gitignored. Contains: `registry.yaml` (targets + publish sink), `reports/`, `baselines/`, `cache/`, `audit.jsonl.d/`. Config files in `config/` are shipped; runtime state in `state/` is not.

## Current Release

v0.2.0 — Phase 1 (local scan) + Phase 2 (SSH remote scan + publish). See `planning/phase3-inputs.md` for next-phase context.

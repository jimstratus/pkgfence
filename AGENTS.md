<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# pkgfence

## Purpose
Multi-codebase dependency and supply-chain vulnerability scanner. Scans local repos and remote SSH hosts for known CVEs, malicious packages (OSV MAL-* lookups), and behavioral red flags. Produces ranked, triaged reports with YAML frontmatter in markdown, SARIF, and JSONL formats. Publishes results to centralized sinks via SCP.

Current release: **v0.3.0** (Phase 3a: EPSS enrichment + Triple-Score ranking).

## Key Files

| File | Description |
|------|-------------|
| `pyproject.toml` | Project manifest — entry point is `scripts.scan_command:main`, Python >=3.11 |
| `CHANGELOG.md` | Release history, v0.2.0 at top |
| `README.md` | User-facing documentation |
| `SKILL.md` | Claude Code skill definition for invoking pkgfence from other projects |
| `LICENSE` | MIT license |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `scripts/` | Core application code — L1-L4 pipeline modules + CLI (see `scripts/AGENTS.md`) |
| `tests/` | 179 pytest tests — unit, integration, safety invariants (see `tests/AGENTS.md`) |
| `config/` | Registry schema, defaults, exclusions (see `config/AGENTS.md`) |
| `planning/` | Phase plans, dogfood reports, handoff docs (see `planning/AGENTS.md`) |
| `references/` | Scanner docs, threat-intel API refs, workflow docs (see `references/AGENTS.md`) |
| `assets/` | Scanner binary hash pins (see `assets/AGENTS.md`) |
| `.github/` | CI workflows (see `.github/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- **Entry point:** `scripts/scan_command.py` wires L1 Discovery -> L2 Scanner -> L3 Enrichment -> L4 Triage -> Output
- **Editable install:** `pip install -e ".[dev]"` in a venv; the CLI is `pkgfence scan`
- **State directory (`state/`)** is gitignored — contains `registry.yaml`, reports, baselines, audit logs
- **Windows + Git Bash:** Use Unix shell syntax. Prefix `MSYS_NO_PATHCONV=1` when passing POSIX paths to argparse
- **SSH calls:** Always use `-o IdentitiesOnly=yes` when specifying `-i <keyfile>`
- **Never run infrastructure commands locally** — all remote work goes through SSH

### Safety Invariants (load-bearing, tested)
| # | Promise | Enforcement |
|---|---------|-------------|
| S1 | SSH unreachable raises `SSHUnreachableError`, never silent local fallback | `ssh_runner.py` + `test_safety_invariants.py` |
| S2 | No package-manager install commands anywhere in scripts | Static regex over `scripts/**/*.py` |
| S3 | SSH command allowlist — only `find`, `cat`, `sha256sum`, `ls`, `stat`, `osv-scanner`, `trivy`, `zizmor` | `ALLOWED_COMMANDS` frozenset |
| S4 | No remote file content exfiltration — only paths, hashes, scanner JSON transit | Static regex over `scan_remote.py` + `discover_remote.py` |

**If any safety invariant test fails, the tool is broken and must NOT be run until fixed.**

### Testing Requirements
- Run `pytest` (179 tests) before any commit
- Safety invariant tests (`test_safety_invariants.py`, `test_s4_no_remote_content_exfil.py`) are non-negotiable
- Use `patch("scripts.<module>.subprocess.run")` — never bare `patch("subprocess.run")`
- No inline imports in test bodies — always module-level

### Architectural Patterns
- **Dependency injection:** `SSHRunner` is passed IN to remote modules, never constructed inside
- **SCAN_ERROR records flow through:** One bad target produces a SCAN_ERROR Finding that flows through L3/L4 unchanged
- **Shared constants:** `DEFAULT_EXCLUDES` and `MANIFEST_ECOSYSTEM` live in `scripts/discover.py`, imported by remote modules
- **TypedDicts over dataclasses:** Findings are plain dicts that roundtrip through JSON/YAML trivially
- **`YAML(typ="rt")`** for insertion order preservation; never `typ="safe"` when dict order matters
- **`encoding="utf-8", errors="replace"`** on every `subprocess.run` call (Windows cp1252 fix)

### Anti-Patterns to Avoid
- No `isolation: "worktree"` for executor subagents
- No mocking subprocess.run at the bare name — use full module path
- No inline imports in test bodies
- No `typ="safe"` when dict order matters
- No passing unquoted arguments through the remote shell — use `shlex.quote()`

## Dependencies

### External
- `ruamel.yaml 0.18.6` — YAML round-trip parsing (preserves comments + insertion order)
- `httpx[http2] 0.27.2` — HTTP client for KEV/OSV/EPSS API calls
- `jsonschema 4.23.0` — Registry schema validation
- `portalocker 2.10.1` — Cross-platform file locking for atomic writes
- `osv-scanner` (system binary) — The actual vulnerability scanner invoked via subprocess
- `trivy`, `zizmor` (optional) — Additional S3-allowlisted scanners

### Dev
- `pytest 8.3.4` + `pytest-cov` + `pytest-mock`

### Phase 3a additions (v0.3.0)
- `scripts/lib/epss_client.py` — EPSS CSV download + 24h TTL cache
- `scripts/lib/priority.py` — Triple-score formula: `0.4*CVSS + 0.3*EPSS + 0.3*KEV`
- `scripts/enrich_epss.py` — L3.5 enrichment stage

<!-- MANUAL: -->

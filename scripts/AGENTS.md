<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# scripts

## Purpose
Core application code implementing the L1-L4 scanning pipeline plus CLI entry points. Each module maps to one pipeline layer. The `lib/` subdirectory contains shared infrastructure (types, clients, runner, registry).

## Key Files

| File | Description |
|------|-------------|
| `__init__.py` | Package marker (empty) |
| `scan_command.py` | **Entry point** — wires L1-L4 + publish, CLI argparse, `run_scan()` function |
| `discover.py` | L1 local discovery — walks registry roots, finds manifests by ecosystem |
| `discover_remote.py` | L1 remote discovery — `find` + `sha256sum` over SSH, imports `DEFAULT_EXCLUDES` from `discover.py` |
| `scan_local.py` | L2 local scanning — invokes `osv-scanner` subprocess per manifest |
| `scan_remote.py` | L2 remote scanning — runs `osv-scanner` on remote host via SSH, only JSON transits back |
| `enrich_threats.py` | L3 enrichment — correlates findings with CISA KEV for exploit status |
| `triage.py` | L4 triage — dedup via PURL, MAL-* override, exceptions, exclusions, severity sort |
| `report.py` | Output — renders markdown report with YAML frontmatter (`_build_frontmatter`) |
| `publish.py` | Publish — SCP sink pushes `.md`/`.sarif`/`.jsonl` to centralized report server |
| `registry_cli.py` | Registry management CLI — `add-root`, `add-project`, `add-ssh`, `list`, `remove` |
| `ssh_precheck.py` | Diagnostic CLI — `pkgfence ssh precheck <name>` verifies host reachable + osv-scanner present |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `lib/` | Shared infrastructure: types, SSH runner, registry, API clients (see `lib/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- **Pipeline flow:** `scan_command.py` calls L1 → L2 → L3 → L4 → Output → Publish in sequence
- **Local/remote split:** Each layer has a local module and a remote module (e.g., `discover.py` + `discover_remote.py`)
- **`SSHRunner` is injected** — remote modules receive it as a parameter, never construct it
- **Shared constants:** `DEFAULT_EXCLUDES` and `MANIFEST_ECOSYSTEM` live in `discover.py` and are imported by `discover_remote.py` — never duplicate
- **S4 invariant:** `scan_remote.py` and `discover_remote.py` must NEVER retrieve remote file contents — only paths, hashes, and scanner JSON stdout may transit

### Testing Requirements
- Every module has a corresponding `tests/test_<module>.py`
- Mock `subprocess.run` as `patch("scripts.<module>.subprocess.run")` — never the bare name
- Remote modules: mock `SSHRunner` via dependency injection, don't patch it globally
- Safety invariant tests (`test_safety_invariants.py`, `test_s4_no_remote_content_exfil.py`) run static regex over these files

### Common Patterns
- `encoding="utf-8", errors="replace"` on every `subprocess.run` call
- `SSHRunner` shell-quotes every remote argument centrally — callers must NOT pre-quote or pre-escape (pass bare `(` `)` for find grouping)
- Findings are `list[Finding]` (TypedDict from `lib/types.py`) — not raw dicts
- Remote manifests are `list[RemoteManifest]` (TypedDict from `lib/remote_types.py`)
- SCAN_ERROR findings flow through unchanged — never filter or block on them

## Dependencies

### Internal
- `scripts/lib/` — all shared types, clients, and infrastructure

### External
- `ruamel.yaml` — YAML loading/writing in `scan_command.py`, `registry_cli.py`
- `subprocess` — invokes `osv-scanner` (local) and `ssh` (remote)

<!-- MANUAL: -->

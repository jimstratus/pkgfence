<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# lib

## Purpose
Shared infrastructure for the pkgfence scanning pipeline. Contains type definitions, API clients, SSH runner, registry management, logging, and output formatters. Every pipeline module in `scripts/` depends on this directory.

## Key Files

| File | Description |
|------|-------------|
| `__init__.py` | Package marker (empty) |
| `types.py` | Core `Finding` TypedDict + `Severity`, `DiffStatus`, `Status` literals — the central data type |
| `remote_types.py` | `RemoteManifest` TypedDict for SSH-discovered manifests (Phase 2) |
| `ssh_runner.py` | `SSHRunner` class — S1 (no local fallback) + S3 (command allowlist) + key_file/use_sudo/port support |
| `registry.py` | `load_registry()`, `save_registry_atomic()` — schema validation via jsonschema, round-trip YAML |
| `kev_client.py` | CISA KEV HTTP client — fetches known-exploited-vulnerabilities catalog, local cache |
| `osv_client.py` | OSV.dev HTTP client — vulnerability lookups by PURL |
| `purl.py` | PURL canonicalization — normalizes package URLs for dedup |
| `config.py` | `load_defaults()` — reads `config/defaults.yaml` |
| `exceptions.py` | `load_exceptions()` — reads `state/exceptions.yaml` for waived findings |
| `baseline.py` | `save_baseline()`, `load_baseline()`, `diff_findings()` — NEW/CHANGED/EXISTING tracking |
| `audit_log.py` | `append_audit_record()` — atomic JSONL audit log writes with portalocker |
| `sarif.py` | `findings_to_sarif()` — converts findings to SARIF 2.1.0 format |
| `logger.py` | `get_logger()` — standardized logging setup |
| `SAFETY_INVARIANTS.md` | Documentation of S1-S4 invariants with rationale and test references |

## For AI Agents

### Working In This Directory
- **`types.py` is the gravity center** — `Finding` TypedDict flows through every pipeline stage. Changes here affect everything.
- **`ssh_runner.py` enforces S1 + S3** — `SSHUnreachableError` must NEVER be caught and converted to local fallback. `ALLOWED_COMMANDS` frozenset is the SSH command allowlist.
- **`registry.py` uses `YAML(typ="rt")`** (round-trip) to preserve comments and insertion order. Never switch to `typ="safe"`.
- **Dependency injection pattern:** `SSHRunner` instances are created in `scan_command.py` and passed to remote modules — never constructed inside lib consumers.
- **`encoding="utf-8", errors="replace"`** on all subprocess calls (Windows cp1252 defense).

### Testing Requirements
- Each module has a corresponding test in `tests/` (e.g., `test_kev_client.py`, `test_purl.py`, `test_baseline.py`)
- `SSHRunner` tests: `test_safety_invariants.py` (S1/S3), `test_ssh_runner_extensions.py` (key_file/sudo/port)
- Registry tests: `test_registry_validation.py` (schema conformance)
- Mock HTTP clients with `pytest-mock` — never hit real APIs in tests

### Common Patterns
- TypedDicts (not dataclasses) because findings flow through JSON/YAML/subprocess — plain dicts roundtrip trivially
- `portalocker` for atomic file writes (audit log, baselines)
- `httpx` for HTTP clients (KEV, OSV) with local file-based cache

## Dependencies

### Internal
- `config/registry.schema.yaml` — loaded by `registry.py` for validation
- `config/defaults.yaml` — loaded by `config.py`

### External
- `ruamel.yaml 0.18.6` — YAML round-trip parsing
- `httpx[http2] 0.27.2` — HTTP client for KEV/OSV APIs
- `jsonschema 4.23.0` — registry schema validation
- `portalocker 2.10.1` — cross-platform file locking

<!-- MANUAL: -->

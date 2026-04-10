<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# tests

## Purpose
179 pytest tests covering unit, integration, safety invariants, and ecosystem validation. Organized as one test file per source module, plus dedicated safety invariant test files.

## Key Files

| File | Description |
|------|-------------|
| `conftest.py` | Shared fixtures: `tmp_state` (isolated state dir), `tmp_registry` (empty registry.yaml) |
| `test_safety_invariants.py` | S1 (no silent local fallback), S2 (no install commands), S3 (SSH allowlist) |
| `test_s4_no_remote_content_exfil.py` | S4 — static regex checks that remote modules never retrieve file contents |
| `test_scan_command.py` | End-to-end scan pipeline tests |
| `test_scan_command_ssh.py` | Scan pipeline with SSH targets |
| `test_scan_local.py` | L2 local scanner orchestration |
| `test_scan_remote.py` | L2 remote scanner (mocked SSHRunner) |
| `test_discover.py` | L1 local manifest discovery |
| `test_discover_remote.py` | L1 remote manifest discovery |
| `test_enrich_threats.py` | L3 KEV enrichment |
| `test_triage.py` | L4 dedup, MAL-* override, exceptions, sorting |
| `test_publish.py` | SCP publish sink |
| `test_ssh_precheck.py` | SSH precheck diagnostic CLI |
| `test_ssh_runner_extensions.py` | SSHRunner key_file, use_sudo, port features |
| `test_report.py` | Markdown report + frontmatter generation |
| `test_registry_cli_ssh.py` | Registry CLI add-ssh command |
| `test_registry_validation.py` | Registry schema validation |
| `test_ecosystems.py` | Ecosystem manifest mapping |
| `test_kev_client.py` | CISA KEV HTTP client |
| `test_osv_client.py` | OSV.dev HTTP client |
| `test_purl.py` | PURL canonicalization |
| `test_sarif.py` | SARIF output generation |
| `test_baseline.py` | Baseline save/load/diff |
| `test_audit_log_atomicity.py` | Atomic audit log writes |
| `test_config.py` | Defaults config loading |
| `test_exceptions.py` | Exception rule loading |
| `test_logger.py` | Logger setup |
| `test_types.py` | TypedDict validation |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `fixtures/` | Test data: npm and python lockfiles for clean/vulnerable/corrupted scenarios (see `fixtures/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- **One test file per source module** — follow the `test_<module>.py` naming convention
- **All imports at module level** — never use inline imports inside test functions (project anti-pattern)
- **Mock subprocess as `patch("scripts.<module>.subprocess.run")`** — never the bare `patch("subprocess.run")`
- **Use `tmp_state` and `tmp_registry` fixtures** from `conftest.py` for isolation
- **Safety invariant tests are non-negotiable** — if they fail, the tool is broken

### Testing Requirements
- Run full suite: `pytest` (or `python -m pytest -v --strict-markers`)
- Run safety tests specifically: `pytest tests/test_safety_invariants.py tests/test_s4_no_remote_content_exfil.py -v`
- CI runs on Python 3.11 (ubuntu-latest) — local dev uses Python 3.14.3

### Common Patterns
- Fixtures create isolated `tmp_path`-based directories with `state/` subdirectory structure
- Remote module tests inject `MagicMock` SSHRunners via function parameters
- `Finding` and `RemoteManifest` TypedDicts used for test data — not raw dicts
- Safety tests use static regex over source files — no mocking needed

## Dependencies

### Internal
- `scripts/` — all modules under test
- `fixtures/` — test lockfiles

### External
- `pytest 8.3.4` — test framework
- `pytest-mock 3.14.0` — `mocker` fixture for patching
- `pytest-cov 5.0.0` — coverage reporting

<!-- MANUAL: -->

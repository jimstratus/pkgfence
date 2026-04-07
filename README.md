# pkgfence

Multi-codebase dependency and supply-chain vulnerability scanner, delivered as a Claude Code skill.

Scans local repositories for known CVEs (via osv-scanner v2 or OSV API fallback), malicious packages (via OpenSSF Malicious Packages `MAL-*` overlays), and behavioral red flags. Produces ranked, triaged reports with copy-pasteable remediation. Calibrated-trust disclaimers and per-finding cards make it explicit what was scanned and what wasn't.

**Status: 🟢 Phase 1 (Foundation) — IMPLEMENTED.** Local-repo scan mode is runnable.

## What works today (Phase 1)

- `pkgfence scan` mode against local registry roots
- Registry CLI: `validate`, `list`, `add-root`, `add-project`, `remove`
- osv-scanner v2 integration with fallback to OSV API querybatch
- CISA KEV `actively_exploited` enrichment via cveID + alias join
- PURL canonical builder with scoped-npm `%40` percent encoding
- Triple-layered triage: dedup → MAL-* override → expiring exceptions → deterministic sort → hardcoded exclusions
- Diff-aware baseline scanning (NEW vs EXISTING tagging)
- Markdown report + SARIF 2.1.0 + per-run JSONL audit log
- Hard safety invariants S1, S2, S3 enforced by tests
- Four-state exit codes (0 clean / 1 findings / 2 scanner error / 3 config error)
- 105 tests passing, every code path TDD-built

## What's deferred (Phase 2+)

- SSH targets (build remotely, run remotely, fetch JSON)
- GitHub mode (api / clone)
- Watch mode (scheduled monitoring + baseline drift detection)
- Audit mode (deep one-shot review with extra scanners)
- Layer 5 fix-recommendation pipeline (LLM recommend → critic review → text doc)
- EPSS, GHSA, deps.dev, OpenSSF Scorecard enrichment
- Behavioral heuristics (age, lifecycle scripts, provenance)
- Coarse reachability tiering
- Meta mode (audit `.claude/`, `.cursor/`, `mcp.json`)

See `planning/plan.md` for the full roadmap (Phases 2-5 are outlined; Phase 1 is detailed).

## Repository layout

```
pkgfence/
├── README.md                           ← you are here
├── SKILL.md                            ← Claude Code skill entry point
├── LICENSE                             ← MIT
├── pyproject.toml                      ← Python deps + pytest config
├── .gitignore                          ← state/, .venv/, __pycache__/, .omc/
├── assets/
│   └── scanner-hashes.json             ← G9 soft guard: known-good osv-scanner SHA256
├── config/
│   ├── registry.schema.yaml            ← JSON Schema for registry.yaml
│   ├── registry.example.yaml           ← copy this to state/registry.yaml
│   ├── defaults.yaml                   ← canonical tunables (severity, TTLs, exit codes)
│   └── exclusions.yaml                 ← hardcoded low-value finding categories
├── references/                         ← deep reference docs
│   ├── workflows/scan-mode.md
│   ├── scanners/osv-scanner.md
│   └── threat-intel/{cisa-kev.md, osv-api.md}
├── scripts/                            ← Python implementation
│   ├── discover.py                     ← L1 discovery
│   ├── scan_local.py                   ← L2 scanner orchestration
│   ├── enrich_threats.py               ← L3 KEV overlay
│   ├── triage.py                       ← L4 dedup/score/filter
│   ├── report.py                       ← markdown report generator
│   ├── registry_cli.py                 ← CLI (validate/list/add-root/add-project/remove)
│   ├── scan_command.py                 ← entry point: pkgfence scan
│   └── lib/                            ← helpers
│       ├── SAFETY_INVARIANTS.md        ← S1/S2/S3 doc
│       ├── logger.py
│       ├── types.py                    ← Finding TypedDict + new_finding factory
│       ├── config.py                   ← defaults.yaml loader
│       ├── purl.py                     ← canonical PURL builder
│       ├── osv_client.py               ← OSV API querybatch + cache + 429 backoff
│       ├── kev_client.py               ← CISA KEV fetch + cache + degraded mode
│       ├── exceptions.py               ← expiring waivers
│       ├── baseline.py                 ← save/load + NEW/EXISTING diff
│       ├── sarif.py                    ← SARIF 2.1.0 emitter
│       ├── audit_log.py                ← per-run JSONL writer
│       ├── ssh_runner.py               ← Phase 2 SSH command runner (built, not wired)
│       └── registry.py                 ← registry load/validate/atomic-write
├── tests/                              ← 105 tests
│   ├── conftest.py                     ← shared tmp_state, tmp_registry fixtures
│   ├── fixtures/
│   │   ├── npm/{vulnerable,clean,corrupted}/
│   │   └── python/{vulnerable,clean}/
│   ├── test_safety_invariants.py       ← S1/S2/S3 enforcement
│   ├── test_registry_validation.py     ← schema + loader + CLI
│   ├── test_purl.py
│   ├── test_osv_client.py
│   ├── test_kev_client.py
│   ├── test_discover.py
│   ├── test_scan_local.py
│   ├── test_enrich_threats.py
│   ├── test_triage.py
│   ├── test_exceptions.py
│   ├── test_baseline.py
│   ├── test_report.py
│   ├── test_sarif.py
│   ├── test_audit_log_atomicity.py
│   ├── test_scan_command.py            ← end-to-end pipeline tests
│   ├── test_ecosystems.py              ← Layer A fixture tests (npm, python)
│   ├── test_logger.py
│   ├── test_types.py
│   └── test_config.py
└── planning/                           ← historical planning artifacts
    ├── design.md                       ← v2.1 spec (critic-approved)
    ├── plan.md                         ← Phase 1 detailed + 2-5 outlined
    ├── plan-detail-raw.md              ← subagent provenance
    └── research/
        ├── round1-tooling.md
        ├── round2-implementation.md
        └── round3-prior-art.md
```

## Quick start

See `SKILL.md` for the runnable quick-start. Three commands:

```bash
# Bootstrap once
python -m venv .venv && source .venv/Scripts/activate && python -m pip install -e ".[dev]"
scoop install osv-scanner

# Set up your registry
python -m scripts.registry_cli --registry state/registry.yaml add-root D:\projects --tier 1

# Run a scan
python -m scripts.scan_command --registry state/registry.yaml
```

## Hard safety invariants

`pkgfence` enforces three architectural invariants by tests that cannot be skipped:

- **S1**: SSH unreachable raises `SSHUnreachableError`, never silently runs the command locally as a substitute. Tested by `test_no_silent_local_fallback_when_ssh_unreachable`.
- **S2**: Never executes `npm install`, `pip install`, `cargo install`, `gem install`, `bundle install`, or `go install` commands. Tested by `test_no_package_manager_install_anywhere_in_scripts` (static regex scan of all `scripts/**/*.py`).
- **S3**: SSH targets only allow commands in a fixed allowlist (`find, cat, sha256sum, ls, stat, osv-scanner, trivy, zizmor`). Tested by `test_ssh_command_allowlist_refuses_disallowed_commands`.

See `scripts/lib/SAFETY_INVARIANTS.md` for the full doc.

## License

MIT. See `LICENSE`. Permissive license enables third-party audit, which matters because "scanners are now targets" per the TeamPCP attack on Trivy/KICS (Round 3 research).

## Motivation

Two real incidents drove this skill into existence:

1. The 2025 Shai-Hulud npm worm that bricked ~5-6 MacBook Pros by exfiltrating secrets and (in some failure modes) `rm -rf $HOME` via postinstall scripts.
2. A separate SSH server breach via a compromised node dependency in code the operator did not deploy.

`pkgfence` Phase 1 catches the first class via OSV `MAL-*` lookups + lifecycle-script flagging (Phase 3+). Phase 2 SSH support will close the loop on the second class.

## Development

- **Test suite**: `python -m pytest -v` (105 tests, all passing)
- **Coverage**: `python -m pytest --cov=scripts --cov-report=term-missing`
- **Lint**: not yet configured (Phase 5)
- **CI**: not yet configured (Phase 5)

To extend pkgfence, follow the TDD discipline used throughout Phase 1: write the failing test first, run it, watch it fail, write minimal implementation, run it, watch it pass, commit.

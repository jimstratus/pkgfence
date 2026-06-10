# pkgfence — Development Guide

Set up and contribute to the multi-codebase dependency and supply-chain vulnerability scanner.

## Prerequisites

| Dependency | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Runtime |
| osv-scanner | v2+ | Core vulnerability scanner (system binary) |
| Git | any | Repository scanning |
| SSH client | any | Remote host scanning (Pattern B) |

### Installing osv-scanner

```bash
# macOS
brew install osv-scanner

# Windows
scoop install osv-scanner

# Linux
# See https://osv.dev for distribution-specific instructions
```

## First-Time Setup

```bash
# Clone
git clone https://github.com/jimstratus/pkgfence.git
cd pkgfence

# Create virtual environment
python -m venv .venv
source .venv/Scripts/activate   # Windows
# source .venv/bin/activate     # Linux/macOS

# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Set up registry
cp config/registry.example.yaml state/registry.yaml
# Edit state/registry.yaml with your repository paths and SSH targets
```

## Project Structure

```
pkgfence/
├── scripts/                  # Core application code (L1-L4 pipeline)
│   ├── discover.py           # L1a: local manifest discovery
│   ├── discover_remote.py    # L1b: remote SSH discovery
│   ├── scan_local.py         # L2a: local osv-scanner orchestration
│   ├── scan_remote.py        # L2b: remote SSH scanner orchestration
│   ├── enrich_threats.py     # L3: CISA KEV overlay + threat intel
│   ├── triage.py             # L4: dedup, score, filter, sort
│   ├── report.py             # Markdown report generator (YAML frontmatter)
│   ├── publish.py            # SCP publish sink
│   ├── scan_command.py       # CLI entry point: pkgfence scan
│   ├── registry_cli.py       # Registry management CLI
│   ├── ssh_precheck.py       # SSH pre-flight diagnostic
│   └── lib/                  # Shared helpers
│       ├── SAFETY_INVARIANTS.md
│       ├── logger.py
│       ├── types.py          # Finding TypedDict + new_finding factory
│       ├── config.py         # defaults.yaml loader
│       ├── purl.py           # Canonical PURL builder
│       ├── osv_client.py     # OSV API querybatch + cache + 429 backoff
│       ├── kev_client.py     # CISA KEV fetch + cache
│       ├── exceptions.py     # Expiring waivers
│       ├── baseline.py       # Save/load + NEW/EXISTING diff
│       ├── sarif.py          # SARIF 2.1.0 emitter
│       ├── audit_log.py      # Per-run JSONL writer
│       ├── ssh_runner.py     # SSH command runner
│       └── registry.py       # Registry load/validate/atomic-write
├── tests/                    # 179 pytest tests
│   ├── conftest.py           # Shared tmp_state, tmp_registry fixtures
│   ├── fixtures/             # npm + Python test projects (vulnerable/clean/corrupted)
│   ├── test_safety_invariants.py       # S1/S2/S3 enforcement
│   └── test_s4_no_remote_content_exfil.py  # S4 enforcement
├── config/                   # Registry schema, defaults, exclusions
├── references/               # Scanner docs, threat-intel API refs, workflow docs
├── planning/                 # Historical planning artifacts + dogfood reports
├── assets/                   # Scanner binary hash pins (G9 soft guard)
└── .github/                  # CI workflows
```

## Running

### Local Scan

```bash
# Add a local root
python -m scripts.registry_cli --registry state/registry.yaml add-root /path/to/projects --tier 1

# Run scan
python -m scripts.scan_command --registry state/registry.yaml
```

### Remote SSH Scan

```bash
# Add an SSH target
python -m scripts.registry_cli --registry state/registry.yaml add-ssh \
  --name myserver --host myserver.example.com --user pkgfence \
  --tier 1 --discover-paths /var/www:/opt/apps

# Pre-flight check
python -m scripts.scan_command --registry state/registry.yaml ssh precheck myserver

# Run scan (handles local + SSH targets in one pass)
python -m scripts.scan_command --registry state/registry.yaml
```

## Testing

```bash
# Run all 179 tests
python -m pytest -v

# With coverage
python -m pytest --cov=scripts --cov-report=term-missing

# Run safety invariant tests only
python -m pytest tests/test_safety_invariants.py tests/test_s4_no_remote_content_exfil.py -v
```

**Safety invariant tests are non-negotiable.** If `test_safety_invariants.py` or `test_s4_no_remote_content_exfil.py` fail, the tool is broken and must not be run until fixed.

## Key Conventions

### TDD Discipline

Every code path is TDD-built. Follow this order:
1. Write the failing test first
2. Run it, watch it fail
3. Write minimal implementation
4. Run it, watch it pass
5. Commit

### Python

- **TypedDicts over dataclasses** — Findings are plain dicts that roundtrip through JSON/YAML trivially
- **`YAML(typ="rt")`** for insertion order preservation; never `typ="safe"` when dict order matters
- **`encoding="utf-8", errors="replace"`** on every `subprocess.run` call (Windows cp1252 fix)
- **Dependency injection** — `SSHRunner` is passed IN to remote modules, never constructed inside
- **No inline imports in test bodies** — always module-level
- **Use `patch("scripts.<module>.subprocess.run")`** — never bare `patch("subprocess.run")`
- **`shlex.quote()`** for all arguments passed through the remote shell

### Safety Invariants (Load-Bearing)

| # | Promise | Enforcement |
|---|---------|-------------|
| S1 | SSH unreachable raises `SSHUnreachableError`, never silent local fallback | `test_safety_invariants.py` |
| S2 | No package-manager install commands anywhere in scripts | Static regex over `scripts/**/*.py` |
| S3 | SSH command allowlist — only `find`, `cat`, `sha256sum`, `ls`, `stat`, `osv-scanner`, `trivy`, `zizmor` | `ALLOWED_COMMANDS` frozenset |
| S4 | No remote file content exfiltration — only paths, hashes, scanner JSON transit | Static regex over `scan_remote.py` + `discover_remote.py` |

See `scripts/lib/SAFETY_INVARIANTS.md` for the full documentation.

## Anti-Patterns to Avoid

- No `isolation: "worktree"` for executor subagents
- No mocking `subprocess.run` at the bare name — use full module path
- No inline imports in test bodies
- No `typ="safe"` when dict order matters
- No passing unquoted arguments through the remote shell
- No package-manager install commands (`npm install`, `pip install`, etc.) anywhere

## Git Workflow

- Branch from `main` for features and fixes
- Keep commits focused and atomic
- Run `pytest` (all 179 tests) before every commit
- Large changes should be discussed in an issue first

## Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | User-facing overview and quick start |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution process and standards |
| [SKILL.md](SKILL.md) | Claude Code skill definition |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [AGENTS.md](AGENTS.md) | AI agent navigation and conventions |
| [config/registry.schema.yaml](config/registry.schema.yaml) | Registry JSON Schema |
| [config/registry.example.yaml](config/registry.example.yaml) | Example registry configuration |
| [references/workflows/scan-mode.md](references/workflows/scan-mode.md) | Local scan workflow details |
| [references/workflows/ssh-mode.md](references/workflows/ssh-mode.md) | SSH mode workflow (ACL, sudo, publish) |
| [references/workflows/open-source-release.md](references/workflows/open-source-release.md) | Safe private-to-public release workflow |
| [references/scanners/osv-scanner.md](references/scanners/osv-scanner.md) | osv-scanner integration reference |
| [references/threat-intel/](references/threat-intel/) | CISA KEV, OSV API threat intelligence docs |

## CI/CD

GitHub Actions workflow at `.github/workflows/test.yml` runs the full test suite on push and PR. The safety invariant tests are included and must pass for CI to succeed.

## Troubleshooting

### osv-scanner not found

Ensure osv-scanner v2+ is installed and on your PATH. Run `osv-scanner --version` to verify. On Windows, use `scoop install osv-scanner`. See `references/scanners/osv-scanner.md` for version requirements and hash verification.

### SSH connection failures

1. Verify the host is reachable: `ssh -o IdentitiesOnly=yes -i <keyfile> user@host echo ok`
2. Run the pre-flight check: `python -m scripts.scan_command --registry state/registry.yaml ssh precheck <name>`
3. Check that osv-scanner is installed on the remote host
4. Verify `discover_paths` exist on the remote

### Tests failing with ImportError

Ensure you installed in editable mode: `pip install -e ".[dev]"`. The `scripts` package must be importable as a package.

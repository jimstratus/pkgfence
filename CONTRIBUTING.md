# Contributing to pkgfence

Thank you for your interest in contributing to pkgfence! This document covers how to contribute to the multi-codebase dependency and supply-chain vulnerability scanner.

## Code of Conduct

Be respectful. Treat others as you'd want to be treated. No exceptions.

## How to Contribute

### Reporting Bugs

Open an issue on GitHub with:

- A clear, descriptive title
- Steps to reproduce the bug, including the registry configuration used
- Expected vs. actual behavior
- Environment details (OS, Python version, osv-scanner version)
- Any relevant log output or error messages

### Suggesting Enhancements

Open an issue with:

- A clear description of the feature
- The problem it solves
- How it fits into the existing L1-L4 pipeline architecture
- Any security considerations (all remote scanning features must respect safety invariants S1-S4)

### Pull Request Process

1. **Fork the repository** and create a feature branch from `main`.
2. **Discuss first** for large changes — open an issue before writing code.
3. **Follow the TDD discipline** — write the failing test first, watch it fail, write minimal implementation, watch it pass.
4. **Write pytest tests** for all new functionality. The project has 341 tests and every code path is TDD-built.
5. **Run the full test suite** before submitting:
   ```bash
   python -m pytest -v
   ```
6. **Safety invariant tests are non-negotiable** — `test_safety_invariants.py` and `test_s4_no_remote_content_exfil.py` must pass. If any safety invariant test fails, the tool is broken.
7. **Update documentation** (README.md, AGENTS.md, SKILL.md) if your change affects behavior.
8. **Submit the PR** with a clear description linking to the issue.

### Security Disclosures

DO NOT open public issues for security vulnerabilities. Contact the maintainers directly. pkgfence's safety invariants (S1-S4) are load-bearing — anything that could compromise SSH isolation or enable remote code execution must be reported privately.

## Development Environment

See [DEVELOPMENT.md](DEVELOPMENT.md) for complete setup instructions.

### Quick Setup

```bash
# Clone
git clone https://github.com/jimstratus/pkgfence.git
cd pkgfence

# Bootstrap
python -m venv .venv
source .venv/Scripts/activate  # or .venv/bin/activate on Linux
pip install -e ".[dev]"

# Install osv-scanner (required system binary)
# macOS: brew install osv-scanner
# Windows: scoop install osv-scanner
# Linux: see https://osv.dev
```

## Coding Standards

### Python

- **Python 3.11+** (as specified in pyproject.toml)
- **TypedDicts over dataclasses** — findings are plain dicts that roundtrip through JSON/YAML
- **`YAML(typ="rt")`** for insertion order preservation; never `typ="safe"` when dict order matters
- **`encoding="utf-8", errors="replace"`** on every `subprocess.run` call (Windows cp1252 fix)
- **Dependency injection** — `SSHRunner` is passed IN to remote modules, never constructed inside
- **No inline imports in test bodies** — always module-level
- **Use `patch("scripts.<module>.subprocess.run")`** — never bare `patch("subprocess.run")`

### Safety Invariants (load-bearing)

| # | Promise | Enforcement |
|---|---------|-------------|
| S1 | SSH unreachable raises `SSHUnreachableError`, never silent local fallback | `test_safety_invariants.py` |
| S2 | No package-manager install commands anywhere in scripts | Static regex over `scripts/**/*.py` |
| S3 | SSH command allowlist — only `find`, `cat`, `sha256sum`, `ls`, `stat`, `osv-scanner`, `trivy`, `zizmor` | `ALLOWED_COMMANDS` frozenset |
| S4 | No remote file content exfiltration — only paths, hashes, scanner JSON transit | Static regex over `scan_remote.py` + `discover_remote.py` |

### Anti-Patterns to Avoid

- No `isolation: "worktree"` for executor subagents
- No mocking `subprocess.run` at the bare name — use full module path
- No inline imports in test bodies
- No `typ="safe"` when dict order matters
- No passing unquoted arguments through the remote shell — use `shlex.quote()`

## Architecture

The pipeline has four layers:

- **L1 Discovery** — find manifest files (requirements.txt, package-lock.json, etc.)
- **L2 Scanner** — run osv-scanner (local or remote via SSH)
- **L3 Enrichment** — overlay CISA KEV, EPSS, threat intelligence
- **L4 Triage** — dedup, score, filter, sort

Output formats: Markdown (with YAML frontmatter), SARIF 2.1.0, JSONL audit log.

## Documentation

- [README.md](README.md) — user-facing overview and quick start
- [DEVELOPMENT.md](DEVELOPMENT.md) — developer environment and workflow
- [references/workflows/open-source-release.md](references/workflows/open-source-release.md) — safe private-to-public release workflow
- [SKILL.md](SKILL.md) — Claude Code skill definition
- [CHANGELOG.md](CHANGELOG.md) — release history
- [AGENTS.md](AGENTS.md) — AI agent navigation and conventions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# .github

## Purpose
GitHub repository configuration. Contains CI/CD workflow definitions.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `workflows/` | GitHub Actions CI workflows (see `workflows/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- CI runs on `ubuntu-latest` with Python 3.11 (not the local 3.14.3)
- Safety invariant tests are run as a separate verification step in CI

<!-- MANUAL: -->

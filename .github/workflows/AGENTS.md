<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# workflows

## Purpose
GitHub Actions CI pipeline definitions for pkgfence.

## Key Files

| File | Description |
|------|-------------|
| `test.yml` | CI test workflow — runs on push/PR to main. Python 3.11 on ubuntu-latest. Installs editable with dev deps, runs full pytest suite, then verifies safety invariant tests specifically. |

## For AI Agents

### Working In This Directory
- **CI uses Python 3.11** — local dev uses 3.14.3. Ensure compatibility with both.
- **Two-step testing:** First runs full `pytest -v --tb=short`, then specifically runs `tests/test_safety_invariants.py -v` as a separate verification step
- **Triggered on:** push to `main`, PRs targeting `main`

<!-- MANUAL: -->

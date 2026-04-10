<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# fixtures

## Purpose
Test data for ecosystem-specific manifest scanning. Contains real and synthetic lockfiles in clean, vulnerable, and corrupted states for npm and python ecosystems. Used by discovery and scanning tests.

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `npm/` | npm `package-lock.json` fixtures — `clean/`, `vulnerable/`, `corrupted/` variants |
| `python/` | Python `requirements.txt` fixtures — `clean/`, `vulnerable/` variants |

## For AI Agents

### Working In This Directory
- **Add new ecosystem fixtures** here when expanding ecosystem coverage (Phase 5 plans: rust, go, ruby, php, java, docker)
- **Vulnerable fixtures must contain real CVEs** — tests assert specific advisory IDs in scanner output
- **Corrupted fixtures test error handling** — malformed JSON that should produce SCAN_ERROR findings
- **Path convention:** `fixtures/<ecosystem>/<state>/<lockfile>` (e.g., `fixtures/npm/vulnerable/package-lock.json`)

<!-- MANUAL: -->

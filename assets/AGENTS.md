<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# assets

## Purpose
Static assets shipped with pkgfence. Currently contains scanner binary hash pins for integrity verification.

## Key Files

| File | Description |
|------|-------------|
| `scanner-hashes.json` | SHA256 hashes of known-good scanner binaries (osv-scanner). Soft guard — not currently verified end-to-end across multiple scanner hosts. Revisit in Phase 5 quality bar. |

## For AI Agents

### Working In This Directory
- **Hash pins are informational** — they record what was verified at install time but aren't enforced at runtime yet
- **Update hashes** when scanner binaries are upgraded on target hosts

<!-- MANUAL: -->

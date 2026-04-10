<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# scanners

## Purpose
Reference documentation for vulnerability scanners integrated with pkgfence.

## Key Files

| File | Description |
|------|-------------|
| `osv-scanner.md` | osv-scanner v2.x — CLI flags, output format, supported ecosystems, known quirks (e.g., no pyproject.toml extractor) |

## For AI Agents

### Working In This Directory
- **Consult before changing scanner invocation** — documents exact flags and expected output format
- **Known quirk:** osv-scanner v2.3.3 has no `pyproject.toml` extractor — `pyproject.toml` was removed from `MANIFEST_ECOSYSTEM` in v0.2.0
- **Update when scanner is upgraded** — flag behavior may change between versions

<!-- MANUAL: -->

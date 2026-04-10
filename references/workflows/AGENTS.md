<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-10 | Updated: 2026-04-10 -->

# workflows

## Purpose
Operational workflow documentation describing how pkgfence is used in practice — both local scanning and SSH remote scanning.

## Key Files

| File | Description |
|------|-------------|
| `scan-mode.md` | Local scan workflow — registry setup, running scans, reading reports |
| `ssh-mode.md` | SSH remote scan workflow — target setup, ACL configuration, precheck, Pattern B (find+sha256sum+osv-scanner on remote) |

## For AI Agents

### Working In This Directory
- **`ssh-mode.md` documents the operational setup** — ACL patterns, osv-scanner installation path (`/usr/local/bin`), SSH key requirements
- **Update when new operational patterns are added** — watch mode, scheduled scans, new publish sinks
- **Known prerequisite:** bespin required `sudo apt-get install -y acl` before setfacl Pattern A1 worked

<!-- MANUAL: -->

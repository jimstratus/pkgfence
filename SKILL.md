---
name: pkgfence
description: |
  Multi-codebase dependency and supply-chain vulnerability scanner.
  Scans local repos for known CVEs, malicious packages (OpenSSF
  Malicious Packages via OSV MAL-* lookups), and behavioral red flags.
  Produces ranked, triaged reports with calibrated-trust disclaimers.

  Use when the user asks: "scan my repos for vulnerabilities", "check
  my dependencies", "is CVE-X in any of my projects", "check if I'm
  exposed to a breach", "supply chain audit", "scan local code for
  known vulnerabilities", or any variant on "find security issues in
  my dependencies."

  DO NOT use for: code review (use security-review or semgrep skill),
  secrets scanning (use Gitleaks), or anything outside dependency /
  supply chain scope.

  Phase 2 (current, v0.2.0): scans local registry roots AND remote SSH
  targets (Pattern B — osv-scanner runs on the remote, only JSON transits
  locally). Reports include YAML frontmatter for machine parsing and can
  be auto-published to a central scp sink. GitHub orgs, watch mode, audit
  mode, and the fix-recommendation pipeline are deferred to later phases.
allowed-tools: Read, Grep, Glob, Bash, WebFetch, Task
license: LICENSE
---

# pkgfence

Multi-codebase dependency / supply-chain vulnerability scanner. Phase 1
ships scan mode for local registry roots.

## Quick start

1. **Install pkgfence's runtime deps** (one-time, in a virtualenv):
   ```bash
   cd D:/projects/pkgfence
   python -m venv .venv
   source .venv/Scripts/activate  # Git Bash on Windows
   python -m pip install -e ".[dev]"
   ```

2. **Install osv-scanner via scoop** (one-time):
   ```bash
   scoop install osv-scanner
   ```

3. **Create a registry**:
   ```bash
   python -m scripts.registry_cli --registry state/registry.yaml add-root D:\projects --tier 1
   python -m scripts.registry_cli --registry state/registry.yaml validate
   ```

4. **Run a scan**:
   ```bash
   python -m scripts.scan_command --registry state/registry.yaml
   ```

5. **Read the report** at `state/reports/<run-id>.md`. Exit codes:
   - `0` = clean
   - `1` = findings at or above the fail-on threshold
   - `2` = scanner error
   - `3` = configuration / registry error

## Architecture (5 layers)

```
L5: Fix Recommendation Pipeline (DEFERRED to Phase 4)
L4: Triage     — dedup, MAL-* override, expiring exceptions, sort, exclusions
L3: Enrichment — CISA KEV actively_exploited overlay
L2: Scanner    — osv-scanner v2 primary, OSV API fallback
L1: Discovery  — walk registry roots (Phase 1: local only)
```

Read [`references/workflows/scan-mode.md`](references/workflows/scan-mode.md)
for the full scan-mode workflow.

Read [`references/scanners/osv-scanner.md`](references/scanners/osv-scanner.md)
when invoking osv-scanner.

Read [`references/threat-intel/cisa-kev.md`](references/threat-intel/cisa-kev.md)
for CISA KEV feed details.

Read [`references/threat-intel/osv-api.md`](references/threat-intel/osv-api.md)
for OSV.dev API gotchas.

## Hard safety invariants (load-bearing)

See [`scripts/lib/SAFETY_INVARIANTS.md`](scripts/lib/SAFETY_INVARIANTS.md).

- **S1**: SSH unreachable raises, never silent local fallback
- **S2**: Never executes package-manager install commands (npm install,
  pip install, cargo install, etc.) — pkgfence reads lockfiles only
- **S3**: SSH command allowlist — only find/cat/sha256sum/ls/stat/scanner
  binaries can run on remote hosts (Phase 2+ wires this)

## What pkgfence does NOT do

- Source code review (use `security-review` or `semgrep` skill)
- Secrets scanning (use Gitleaks or TruffleHog)
- Modify your project files (no auto-fix, no git commits, no PRs)
- Run package-manager install commands (S2 invariant)
- Anything in Phase 3+ (GitHub orgs, watch mode, audit mode, fix
  recommendations, behavioral heuristics, EPSS/GHSA/Scorecard enrichment)
  — see `planning/plan.md` for the roadmap.

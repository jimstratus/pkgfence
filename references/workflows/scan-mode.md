# scan-mode workflow

The `pkgfence scan` command runs the full L1→L2→L3→L4→output pipeline against a registry.

## Entry points

- **CLI**: `python -m scripts.scan_command [OPTIONS]`
- **Programmatic**: `from scripts.scan_command import run_scan; run_scan(registry_path, state_dir, ...)`

## CLI options

| Flag | Default | Meaning |
|---|---|---|
| `--registry PATH` | `state/registry.yaml` | Path to the registry YAML |
| `--state PATH` | `state` | Pkgfence state directory (reports/, baselines/, cache/, audit.jsonl.d/) |
| `--path PATH` | `None` | Ad-hoc directory to scan, bypasses the registry entirely |
| `--fail-on LEVEL` | `critical` | Severity floor for exit code 1 (critical/high/medium/low/info) |

## Pipeline

```
L0: Config + Registry
    Load config/defaults.yaml; load state/registry.yaml or build synthetic
    from --path. Exit 3 on parse / schema error.

L1: Discovery
    discover_manifests_full(roots, projects, tier_filter={1})
    Walk registry roots shallowly (max depth 4, max 10k files).
    Yield (target, path, ecosystem, manifest_hash, tier) per manifest.

L2: Scanner Orchestration
    scan_all_manifests(manifests) per manifest:
      - detect osv-scanner via --version
      - if installed: subprocess osv-scanner -L <lockfile> --format json
        - exit 0 = no vulns, 1 = vulns found (BOTH SUCCESS), 2 = error,
          127 = not found, 128 = empty/malformed lockfile
      - if NOT installed (or non-npm with no fallback): SCAN_ERROR finding
      - if installed BUT exit 128: EmptyLockfileError → SCAN_ERROR finding
      - npm fallback: parse package-lock.json → OSVClient.querybatch()
    Returns list[Finding] including SCAN_ERROR records for failed targets.

L3: Threat Enrichment
    KEVClient.refresh() (24h TTL cache, marks degraded on fetch fail)
    enrich_with_kev(findings, kev): for each finding, check vuln_id AND
    aliases[] against the KEV cveID set. Sets actively_exploited=True
    when matched. Round 2 finding: KEV joins via cveID only, so we MUST
    check aliases.

L4: Triage
    dedup_findings: dedup by (purl, vuln_id) tuple
    apply_mal_override: any MAL-* in id or aliases → severity=critical,
                        mal_flagged=True, remediation="Remove immediately"
    apply_exceptions: filter out findings matching active expiring waivers
    apply_exclusions: filter out info-severity and excluded categories
    sort_findings: deterministic by (severity_rank, purl, vuln_id)

Baseline
    load_baseline(state/baselines/default.json)
    diff_findings(current, baseline): tag NEW vs EXISTING
    save_baseline: write updated state

Output
    render_markdown_report → state/reports/<run-id>.md
    findings_to_sarif → state/reports/<run-id>.sarif
    append_audit_record → state/audit.jsonl.d/<run-id>.jsonl
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no findings at or above the `--fail-on` floor |
| `1` | Findings present at or above the floor |
| `2` | Scanner error (real, not the exit-1-vulns-found case) |
| `3` | Configuration / registry error (invalid YAML, missing schema, etc.) |

## Output files

After every scan:

- `state/reports/<run-id>.md` — markdown report (calibrated-trust disclaimer + snapshot + finding cards)
- `state/reports/<run-id>.sarif` — SARIF 2.1.0 (severity → error/warning/note/none mapping)
- `state/audit.jsonl.d/<run-id>.jsonl` — append-only audit log (one record per scan)
- `state/baselines/default.json` — updated baseline for next-run diff

## Degraded mode

If any threat-intel feed (currently only CISA KEV) fails or is rate-limited, the report header includes a `⚠️ Degraded mode` block listing exactly which feed failed. The scan completes and findings are still reported, but enrichment is missing — the user knows the report is partial.

## Diff-aware default

Subsequent scans compare to `state/baselines/default.json` and tag each finding with `diff_status`:

- `NEW` — not in baseline
- `EXISTING` — in baseline (same purl + vuln_id + manifest_path)

Phase 2+ adds `CHANGED` (severity drift, fix-version drift).

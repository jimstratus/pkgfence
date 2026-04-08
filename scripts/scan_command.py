"""pkgfence scan command — entry point for the scan mode.

Wires Layers 1-4 together:
    L1 Discovery -> L2 Scanner -> L3 Enrichment -> L4 Triage -> Output

Usage (from CLI):
    python -m scripts.scan_command [--registry path] [--state state-dir]
                                    [--path adhoc-path] [--fail-on level]
"""
import argparse
import datetime
import json
import sys
import uuid
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from scripts.discover import discover_manifests_full
from scripts.scan_local import scan_all_manifests, detect_scanner
from scripts.discover_remote import discover_remote_safely
from scripts.scan_remote import scan_remote_manifests
from scripts.lib.ssh_runner import SSHRunner
from scripts.enrich_threats import enrich_with_kev
from scripts.triage import (
    dedup_findings,
    apply_mal_override,
    apply_exceptions,
    sort_findings,
    apply_exclusions,
)
from scripts.report import render_markdown_report
from scripts.lib.baseline import save_baseline, load_baseline, diff_findings
from scripts.lib.kev_client import KEVClient
from scripts.lib.registry import load_registry, RegistryError
from scripts.lib.remote_types import RemoteManifest
from scripts.lib.config import load_defaults, DefaultsError
from scripts.lib.exceptions import load_exceptions
from scripts.lib.audit_log import append_audit_record
from scripts.lib.sarif import findings_to_sarif
from scripts.lib.logger import get_logger

log = get_logger(__name__)


SKILL_ROOT = Path(__file__).parent.parent
DEFAULT_EXCLUSIONS_PATH = SKILL_ROOT / "config" / "exclusions.yaml"


def _load_exclusions_config(path: Path) -> dict[str, Any]:
    """Load exclusions.yaml as a plain dict. Returns empty dict on missing/parse err."""
    if not path.exists():
        return {}
    try:
        loader = YAML(typ="safe")
        data = loader.load(path.read_text(encoding="utf-8"))
        return data or {}
    except YAMLError as e:
        log.warning("exclusions parse failed at %s: %s", path, e)
        return {}


def run_scan(
    registry_path: Path,
    state_dir: Path,
    adhoc_path: Path | None = None,
    fail_on: str = "critical",
) -> tuple[int, Path]:
    """Execute the scan mode end-to-end.

    Args:
        registry_path: Path to registry.yaml (ignored if adhoc_path is set)
        state_dir: pkgfence state directory (reports/, baselines/, cache/, audit.jsonl.d/)
        adhoc_path: Optional one-off path to scan, bypassing the registry
        fail_on: Severity floor for exit code 1 (critical|high|medium|low|info)

    Returns:
        (exit_code, report_path) tuple

    Exit codes:
        0 = clean (no findings at or above fail_on level)
        1 = findings present at or above fail_on level
        2 = scanner error (real one, not just exit-1-vulns)
        3 = configuration / registry error
    """
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "reports").mkdir(exist_ok=True)
    (state_dir / "baselines").mkdir(exist_ok=True)
    (state_dir / "cache").mkdir(exist_ok=True)

    run_id = (
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    log.info("scan run %s started", run_id)

    # Layer 0: load config + registry
    try:
        load_defaults()
    except DefaultsError as e:
        print(f"Error loading defaults: {e}", file=sys.stderr)
        return 3, state_dir / "reports" / f"{run_id}-error.md"

    if adhoc_path is not None:
        # Build a synthetic registry on the fly — bypasses schema validation
        reg = {
            "version": 1,
            "roots": [{"path": str(adhoc_path), "tier": 1}],
            "projects": [],
            "ssh": [],
            "github": [],
        }
    else:
        try:
            reg = load_registry(registry_path)
        except RegistryError as e:
            print(f"Error loading registry: {e}", file=sys.stderr)
            return 3, state_dir / "reports" / f"{run_id}-error.md"

    # Layer 1: Discovery
    log.info("L1 discovery starting")
    manifests = list(
        discover_manifests_full(
            roots=list(reg.get("roots") or []),
            projects=list(reg.get("projects") or []),
            tier_filter={1},  # default tier 1 only
        )
    )
    log.info("L1 discovered %d manifests", len(manifests))

    # Layer 1b: Remote discovery via SSH targets
    # Tier filter mirrors the local tier_filter={1} passed to discover_manifests_full above.
    ssh_targets = list(reg.get("ssh") or [])
    tier_set = {1}
    filtered_ssh = [t for t in ssh_targets if t.get("tier", 1) in tier_set]
    # Build each SSHRunner once per target and reuse for L1b + L2b.
    # SSHRunner is stateless today, but if connection pooling lands later we
    # want a single pooled instance per target per scan, not two.
    target_runners: dict[str, SSHRunner] = {
        t["name"]: SSHRunner(
            host=t["host"],
            user=t["user"],
            key_file=t.get("key_file"),
            use_sudo=t.get("use_sudo", False),
        )
        for t in filtered_ssh
    }
    remote_manifests: list[RemoteManifest] = []
    for target in filtered_ssh:
        remote_manifests.extend(
            discover_remote_safely(target, target_runners[target["name"]])
        )
    log.info("L1 remote discovered %d manifests across %d ssh targets",
             len(remote_manifests), len(filtered_ssh))

    # Layer 2: Scanner orchestration
    log.info("L2 scanner orchestration starting")
    findings = scan_all_manifests(manifests)
    log.info("L2 found %d raw findings", len(findings))

    # Layer 2b: Remote scanning (reuses the SSHRunner built in L1b; SCAN_ERROR
    # records already in remote_manifests for unreachable targets pass through)
    for target in filtered_ssh:
        target_manifests = [m for m in remote_manifests if m.get("target") == target["name"]]
        if not target_manifests:
            continue
        findings.extend(
            scan_remote_manifests(target_manifests, target_runners[target["name"]])
        )
    log.info("L2 total findings (local + remote): %d", len(findings))

    # Layer 3: Threat enrichment
    log.info("L3 threat enrichment starting")
    degraded_modes: list[str] = []
    kev = KEVClient(cache_dir=state_dir / "cache" / "kev")
    try:
        kev.refresh()
    except Exception as e:  # noqa: BLE001 — any refresh failure = degraded
        log.warning("KEV refresh failed: %s", e)
        degraded_modes.append(f"CISA KEV unreachable: {e}")
    if getattr(kev, "is_degraded", False):
        degraded_modes.append("CISA KEV feed degraded — exploit-status not enriched")
    findings = enrich_with_kev(findings, kev)

    # Layer 4: Triage
    log.info("L4 triage starting")
    findings = dedup_findings(findings)
    findings = apply_mal_override(findings)

    exceptions_path = state_dir / "exceptions.yaml"
    exceptions = load_exceptions(exceptions_path)
    findings = apply_exceptions(findings, exceptions)

    exclusions_cfg = _load_exclusions_config(DEFAULT_EXCLUSIONS_PATH)
    findings = apply_exclusions(findings, exclusions_cfg)

    findings = sort_findings(findings)

    # Baseline diff
    baseline_path = state_dir / "baselines" / "default.json"
    prior_baseline = load_baseline(baseline_path)
    prior_findings = (prior_baseline or {}).get("findings") if prior_baseline else None
    findings = diff_findings(findings, prior_findings)

    # Save updated baseline
    save_baseline(
        baseline_path,
        {
            "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "manifest_hashes": {
                m["path"]: m.get("manifest_hash", "") for m in manifests
            },
            "findings": findings,
        },
    )

    # Output: markdown report
    snapshot = {
        "scanner_version": detect_scanner("osv-scanner") or "osv-api-fallback",
        "kev_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "targets_scanned": len(manifests) + len(remote_manifests),
        "packages_checked": len(findings),  # rough proxy
    }
    report_md = render_markdown_report(findings, snapshot, degraded_modes)
    report_path = state_dir / "reports" / f"{run_id}.md"
    report_path.write_text(report_md, encoding="utf-8")
    log.info("wrote report to %s", report_path)

    # SARIF output
    sarif = findings_to_sarif(findings, scanner_version=snapshot["scanner_version"])
    sarif_path = state_dir / "reports" / f"{run_id}.sarif"
    sarif_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    # JSONL audit log
    append_audit_record(
        state_dir,
        run_id,
        {
            "run_id": run_id,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "manifests_scanned": len(manifests) + len(remote_manifests),
            "findings_count": len(findings),
            "degraded_modes": degraded_modes,
        },
    )

    # Exit code logic
    fail_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        fail_on, 0
    )
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    has_failing = any(
        sev_rank.get(f.get("severity", "medium"), 99) <= fail_rank
        and f.get("status") != "SCAN_ERROR"
        for f in findings
    )
    exit_code = 1 if has_failing else 0
    log.info("scan complete: exit %d, %d findings", exit_code, len(findings))

    return exit_code, report_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pkgfence scan")
    parser.add_argument(
        "--registry", default="state/registry.yaml", help="Path to registry.yaml"
    )
    parser.add_argument(
        "--state",
        default="state",
        help="State directory (reports/, baselines/, cache/, audit.jsonl.d/)",
    )
    parser.add_argument(
        "--path", default=None, help="Ad-hoc path to scan (bypasses registry)"
    )
    parser.add_argument(
        "--fail-on",
        default="critical",
        choices=["critical", "high", "medium", "low", "info"],
        help="Exit code 1 if findings at this severity or higher",
    )
    args = parser.parse_args(argv)

    try:
        exit_code, _ = run_scan(
            registry_path=Path(args.registry),
            state_dir=Path(args.state),
            adhoc_path=Path(args.path) if args.path else None,
            fail_on=args.fail_on,
        )
        return exit_code
    except Exception as e:  # noqa: BLE001
        log.exception("scan command failed: %s", e)
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

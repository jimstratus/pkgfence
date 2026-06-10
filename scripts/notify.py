"""pkgfence-notify — compare the two most recent scan reports and fire
a notification when new findings appear above a severity threshold.

Exit codes:
    0 = not triggered (no new findings above threshold)
    1 = triggered (new findings found above threshold)
"""
import argparse
import datetime
import logging
import socket
import sys
from io import StringIO
from pathlib import Path

import httpx
from ruamel.yaml import YAML

from scripts.lib.baseline import load_baseline
from scripts.lib.types import is_status_record

log = logging.getLogger(__name__)

SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

ALL_SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _new_findings_from_baseline(baseline: dict) -> dict[str, int]:
    """Per-severity counts of diff_status==NEW findings from the saved
    baseline — the single source of 'newness' (issue #13). Status records
    don't count."""
    counts = {s: 0 for s in ALL_SEVERITIES}
    for f in baseline.get("findings") or []:
        if f.get("diff_status") != "NEW" or is_status_record(f):
            continue
        sev = f.get("severity", "medium")
        if sev in counts:
            counts[sev] += 1
    return counts


def parse_report_frontmatter(report_path: Path) -> dict:
    """Read a pkgfence markdown report and return the YAML frontmatter dict.

    Args:
        report_path: Path to a .md report file with --- frontmatter ---

    Returns:
        Parsed frontmatter as a plain dict.
    """
    text = report_path.read_text(encoding="utf-8")
    # Frontmatter is between the first and second --- markers
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end_idx = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            end_idx = i
            break
    if end_idx is None:
        return {}
    frontmatter_text = "\n".join(lines[1:end_idx])
    yaml = YAML(typ="safe")
    data = yaml.load(StringIO(frontmatter_text))
    return data or {}


def get_two_latest_reports(state_dir: Path) -> tuple[Path, Path] | None:
    """Return the two most recent report paths as (previous, current).

    Reports are sorted by filename (which encodes run_id = timestamp).
    Returns None if fewer than 2 reports exist.

    Args:
        state_dir: pkgfence state directory containing reports/

    Returns:
        (previous, current) Path tuple, or None.
    """
    reports_dir = state_dir / "reports"
    if not reports_dir.exists():
        return None
    reports = sorted(reports_dir.glob("*.md"))
    if len(reports) < 2:
        return None
    return reports[-2], reports[-1]


def check_for_new_findings(state_dir: Path, threshold: str = "critical") -> dict:
    """Compare the two most recent reports and compute the delta.

    Args:
        state_dir: pkgfence state directory
        threshold: severity floor for triggering (critical/high/medium/low/info)

    Returns:
        dict with keys:
            triggered (bool): True if any delta at or above threshold is > 0
            new_findings (dict): per-severity delta (clamped to 0)
            run_id (str): current report run_id
            previous_run_id (str): previous report run_id
            targets (list): ssh_targets from current report
            summary (str): human-readable one-liner
            threshold (str): the threshold used
    """
    pair = get_two_latest_reports(state_dir)
    if pair is None:
        return {
            "triggered": False,
            "new_findings": {s: 0 for s in ALL_SEVERITIES},
            "run_id": "",
            "previous_run_id": "",
            "targets": [],
            "summary": "Not enough reports to compare",
            "threshold": threshold,
        }

    prev_path, curr_path = pair
    prev_fm = parse_report_frontmatter(prev_path)
    curr_fm = parse_report_frontmatter(curr_path)

    prev_sev = prev_fm.get("findings_by_severity") or {}
    curr_sev = curr_fm.get("findings_by_severity") or {}

    # Newness comes from the saved baseline's per-finding diff_status,
    # keyed to the current report by run_id (issue #13: count-deltas miss
    # net-zero churn — one fixed + one new = delta 0 = missed alert).
    baseline = load_baseline(state_dir / "baselines" / "default.json")
    if baseline is not None and baseline.get("run_id") == curr_fm.get("run_id"):
        new_findings = _new_findings_from_baseline(baseline)
    else:
        log.warning(
            "notify: no baseline matching run %s — falling back to "
            "frontmatter count-delta", curr_fm.get("run_id"),
        )
        new_findings = {}
        for sev in ALL_SEVERITIES:
            delta = (curr_sev.get(sev, 0) or 0) - (prev_sev.get(sev, 0) or 0)
            new_findings[sev] = max(0, delta)

    # Check if any delta at or above threshold is > 0
    threshold_rank = SEVERITY_RANK.get(threshold, 0)
    triggered = any(
        new_findings[sev] > 0
        for sev in ALL_SEVERITIES
        if SEVERITY_RANK.get(sev, 99) <= threshold_rank
    )

    run_id = curr_fm.get("run_id", curr_path.stem)
    previous_run_id = prev_fm.get("run_id", prev_path.stem)
    targets = curr_fm.get("ssh_targets") or []

    # Build a concise summary line
    triggered_sevs = [
        sev for sev in ALL_SEVERITIES
        if new_findings[sev] > 0 and SEVERITY_RANK.get(sev, 99) <= threshold_rank
    ]
    if triggered_sevs:
        parts = [f"{new_findings[s]} new {s}" for s in triggered_sevs]
        summary = f"{', '.join(parts)} finding(s) since {previous_run_id}"
    else:
        summary = f"No new findings above {threshold} threshold since {previous_run_id}"

    return {
        "triggered": triggered,
        "new_findings": new_findings,
        "run_id": run_id,
        "previous_run_id": previous_run_id,
        "targets": list(targets),
        "summary": summary,
        "threshold": threshold,
    }


def send_webhook(url: str, payload: dict) -> None:
    """POST the notification payload to a webhook URL.

    Best-effort: catches all exceptions and logs a warning — never raises.

    Args:
        url: Webhook endpoint URL
        payload: JSON-serialisable dict to POST
    """
    try:
        httpx.post(url, json=payload, timeout=10)
    except Exception as exc:  # noqa: BLE001
        log.warning("webhook POST to %s failed: %s", url, exc)


def format_stdout_summary(result: dict) -> str:
    """Format a human-readable summary of the notification result.

    Args:
        result: dict returned by check_for_new_findings

    Returns:
        Multi-line string suitable for printing to stdout.
    """
    lines = [
        f"pkgfence-notify",
        f"  Run:      {result['run_id']}",
        f"  Previous: {result['previous_run_id']}",
        f"  Targets:  {', '.join(result['targets']) if result['targets'] else '(none)'}",
        f"  Threshold: {result['threshold']}",
        f"  Triggered: {result['triggered']}",
        f"  Summary:   {result['summary']}",
    ]
    if result.get("new_findings"):
        new = result["new_findings"]
        sev_parts = [f"{sev}={new.get(sev, 0)}" for sev in ALL_SEVERITIES]
        lines.append(f"  Delta:    {', '.join(sev_parts)}")
    return "\n".join(lines)


def _build_webhook_payload(result: dict, threshold: str, state_dir: Path) -> dict:
    """Construct the full webhook payload from a check_for_new_findings result."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "event": "pkgfence.scan.new_findings",
        "run_id": result["run_id"],
        "timestamp": now.isoformat(),
        "scanner_host": socket.gethostname(),
        "threshold": threshold,
        "new_findings": result["new_findings"],
        "previous_run_id": result["previous_run_id"],
        "targets": result["targets"],
        "report_path": str(state_dir / "reports" / f"{result['run_id']}.md"),
        "summary": result["summary"],
    }


def main(argv=None) -> int:
    """Entry point for pkgfence-notify.

    Args:
        argv: argument list (defaults to sys.argv[1:])

    Returns:
        0 = not triggered, 1 = triggered
    """
    parser = argparse.ArgumentParser(
        prog="pkgfence-notify",
        description="Compare the two most recent pkgfence scan reports and notify on new findings.",
    )
    parser.add_argument(
        "--state",
        required=True,
        help="pkgfence state directory (contains reports/)",
    )
    parser.add_argument(
        "--webhook",
        default=None,
        help="Webhook URL to POST when triggered (optional)",
    )
    parser.add_argument(
        "--threshold",
        default="critical",
        choices=list(SEVERITY_RANK.keys()),
        help="Severity floor for triggering notification (default: critical)",
    )
    args = parser.parse_args(argv)

    state_dir = Path(args.state)
    result = check_for_new_findings(state_dir, threshold=args.threshold)

    print(format_stdout_summary(result))

    if result["triggered"] and args.webhook:
        payload = _build_webhook_payload(result, args.threshold, state_dir=state_dir)
        send_webhook(args.webhook, payload)

    return 1 if result["triggered"] else 0


if __name__ == "__main__":
    sys.exit(main())

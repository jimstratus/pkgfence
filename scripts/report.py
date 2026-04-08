"""Markdown report generator for pkgfence scan output.

The report has these sections:
- YAML frontmatter (machine-readable scan metadata)
- Header (date)
- Calibrated trust disclaimer (M10 critic gap fix)
- Snapshot (scanner version, feed timestamps, targets scanned, packages checked)
- Degraded mode warnings (if any)
- Summary (counts by severity)
- Findings list (grouped by severity, one card per finding)
"""
from io import StringIO
from typing import Any

from ruamel.yaml import YAML

from scripts.lib.types import Finding


def _build_frontmatter(
    findings: list[Finding],
    snapshot: dict[str, Any],
    degraded_modes: list[str],
) -> str:
    """Build a YAML frontmatter block with scan metadata. Enables machine
    parsing by AI agents, yq, log aggregators — no regex guesswork over the
    human-readable body."""
    severity_buckets: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }
    for f in findings:
        sev = f.get("severity", "medium")
        if sev in severity_buckets:
            severity_buckets[sev] += 1

    fm_data = {
        "run_id": snapshot.get("run_id", ""),
        "timestamp": snapshot.get("timestamp", ""),
        "scanner_host": snapshot.get("scanner_host", ""),
        "pkgfence_version": snapshot.get("pkgfence_version", ""),
        "scanner_version": snapshot.get("scanner_version", ""),
        "exit_code": snapshot.get("exit_code", 0),
        "targets_scanned": snapshot.get("targets_scanned", 0),
        "findings_total": len(findings),
        "findings_by_severity": severity_buckets,
        "degraded_modes": [str(m) for m in degraded_modes],
        "ssh_targets": [str(t) for t in snapshot.get("ssh_targets", [])],
        "local_roots": [str(r) for r in snapshot.get("local_roots", [])],
    }

    yaml = YAML(typ="safe")
    yaml.default_flow_style = False
    buf = StringIO()
    yaml.dump(fm_data, buf)
    return "---\n" + buf.getvalue() + "---\n"


_DISCLAIMER_TEMPLATE = (
    '**Calibrated trust disclaimer:** "No findings" does not mean "safe." '
    "It means no patterns matched the queried feeds at the snapshot below. "
    "Supply-chain malware can be live for hours before it is in any feed.\n"
)


def _render_disclaimer() -> str:
    return _DISCLAIMER_TEMPLATE


def _render_snapshot(snapshot: dict[str, Any]) -> str:
    lines = ["**Snapshot:**"]
    if "scanner_version" in snapshot:
        lines.append(f"- Scanner: {snapshot['scanner_version']}")
    if "kev_timestamp" in snapshot:
        lines.append(f"- KEV feed timestamp: {snapshot['kev_timestamp']}")
    if "osv_timestamp" in snapshot:
        lines.append(f"- OSV feed timestamp: {snapshot['osv_timestamp']}")
    if "targets_scanned" in snapshot:
        lines.append(f"- Targets scanned: {snapshot['targets_scanned']}")
    if "packages_checked" in snapshot:
        lines.append(f"- Packages checked: {snapshot['packages_checked']}")
    return "\n".join(lines) + "\n"


def _render_degraded_modes(degraded_modes: list[str]) -> str:
    if not degraded_modes:
        return ""
    lines = ["\u26a0\ufe0f **Degraded mode:**"]
    for mode in degraded_modes:
        lines.append(f"- {mode}")
    return "\n".join(lines) + "\n"


def _render_summary(findings: list[Finding]) -> str:
    if not findings:
        return "**No findings.** Zero vulnerabilities matched in this scan.\n"
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "medium")
        counts[sev] = counts.get(sev, 0) + 1
    parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in counts:
            parts.append(f"{counts[sev]} {sev}")
    return f"**Findings:** {len(findings)} total \u2014 " + ", ".join(parts) + "\n"


def _render_finding_card(f: Finding) -> str:
    sev = f.get("severity", "medium").upper()
    icon = {
        "CRITICAL": "\U0001f534",
        "HIGH": "\U0001f7e0",
        "MEDIUM": "\U0001f7e1",
        "LOW": "\U0001f535",
        "INFO": "\u2139\ufe0f",
    }.get(sev, "\u2022")
    lines = [
        f"### {icon} {sev} \u2014 `{f.get('vuln_id', '?')}`",
        "",
        f"- **Package:** `{f.get('purl', '?')}`",
        f"- **Manifest:** `{f.get('manifest_path', '?')}`",
        f"- **Target:** {f.get('target', '?')}",
    ]
    if f.get("actively_exploited"):
        lines.append("- **\u26a0\ufe0f Actively exploited (CISA KEV)**")
    if f.get("mal_flagged"):
        lines.append("- **\U0001f6a8 OpenSSF Malicious Packages flag (MAL-*)**")
    if f.get("diff_status"):
        lines.append(f"- **Diff status:** {f['diff_status']}")
    if f.get("description"):
        lines.append(f"- **Description:** {f['description']}")
    if f.get("remediation"):
        lines.append(f"- **Remediation:** {f['remediation']}")
    if f.get("status") == "SCAN_ERROR":
        lines.append("- **\u26a0\ufe0f Scanner error \u2014 target not actually scanned**")
    return "\n".join(lines) + "\n"


def render_markdown_report(
    findings: list[Finding],
    snapshot: dict[str, Any],
    degraded_modes: list[str],
) -> str:
    """Render a full scan report as markdown.

    Args:
        findings: list of post-triage Finding records
        snapshot: dict with scanner_version, kev_timestamp, targets_scanned, etc.
        degraded_modes: list of human-readable degradation messages (empty if all OK)

    Returns:
        Markdown string ready to write to disk.
    """
    frontmatter = _build_frontmatter(findings, snapshot, degraded_modes)
    parts = [frontmatter, "# Scan Report\n", _render_disclaimer(), "\n", _render_snapshot(snapshot), "\n"]

    deg = _render_degraded_modes(degraded_modes)
    if deg:
        parts.append(deg + "\n")

    parts.append(_render_summary(findings) + "\n")

    if findings:
        parts.append("## Findings\n\n")
        for f in findings:
            parts.append(_render_finding_card(f) + "\n")

    return "".join(parts)

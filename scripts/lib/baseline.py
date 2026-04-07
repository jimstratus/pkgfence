"""Baseline storage and diff for pkgfence.

A baseline is a snapshot of (manifest_hashes, findings) from a prior scan.
Used by Layer 4 to tag findings as NEW vs CHANGED vs EXISTING in subsequent
scans (diff-aware default mode).

Storage: per-target JSON file under state/baselines/<target-name>.json.
"""
import json
from pathlib import Path
from typing import Any, Optional


def save_baseline(path: Path, baseline: dict[str, Any]) -> None:
    """Write baseline to a JSON file. Creates parent dirs if missing."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")


def load_baseline(path: Path) -> Optional[dict[str, Any]]:
    """Load baseline from a JSON file. Returns None if file doesn't exist."""
    path = Path(path)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _finding_identity(f: dict) -> tuple[str, str, str]:
    """Identity tuple for diff: (purl, vuln_id, manifest_path).

    Includes manifest_path so the same vuln in different manifests doesn't
    incorrectly merge.
    """
    return (f.get("purl", ""), f.get("vuln_id", ""), f.get("manifest_path", ""))


def diff_findings(
    current: list[dict],
    baseline: Optional[list[dict]],
) -> list[dict]:
    """Tag each current finding with diff_status: NEW, CHANGED, or EXISTING.

    NEW       = not in baseline
    EXISTING  = in baseline (same identity)
    CHANGED   = (Phase 2+) when severity or fix_version drifts; for MVP we
                only emit NEW vs EXISTING.

    If baseline is None (first scan, no prior state), all current findings
    are NEW.
    """
    if baseline is None:
        for f in current:
            f["diff_status"] = "NEW"
        return current

    baseline_ids = {_finding_identity(f) for f in baseline}
    for f in current:
        if _finding_identity(f) in baseline_ids:
            f["diff_status"] = "EXISTING"
        else:
            f["diff_status"] = "NEW"
    return current

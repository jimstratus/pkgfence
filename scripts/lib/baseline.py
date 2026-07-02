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
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")


def load_baseline(path: Path) -> Optional[dict[str, Any]]:
    path = Path(path)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _finding_identity(f: dict) -> tuple[str, str, str]:
    return (f.get("purl", ""), f.get("vuln_id", ""), f.get("manifest_path", ""))


def diff_findings(
    current: list[dict],
    baseline: Optional[list[dict]],
) -> list[dict]:
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


def diff_alarms(
    current_hashes: dict[str, str],
    prior_hashes: dict[str, str] | None,
    current_finding_count: int,
    prior_finding_count: int | None,
) -> list[str]:
    """Detect manifest-hash changes that didn't produce new findings.

    Returns a list of human-readable alarm strings. An alarm fires when
    a manifest's hash changed between scans but the total finding count
    didn't increase — suggesting a potentially unauthorized dependency
    change that didn't introduce (or removed) known vulnerabilities.
    """
    if prior_hashes is None:
        return []
    alarms = []
    for path, current_hash in current_hashes.items():
        prior_hash = prior_hashes.get(path)
        if prior_hash and prior_hash != current_hash:
            if prior_finding_count is not None and current_finding_count <= prior_finding_count:
                alarms.append(
                    f"Baseline diff: {path} hash changed "
                    f"({prior_hash[:8]}... → {current_hash[:8]}...) "
                    f"without new findings"
                )
    return alarms

"""Baseline storage and diff for pkgfence.

A baseline is a snapshot of (manifest_hashes, findings) from a prior scan.
Used by Layer 4 to tag findings as NEW vs CHANGED vs EXISTING in subsequent
scans (diff-aware default mode).

Storage: per-target JSON file under state/baselines/<target-name>.json.
"""
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

from scripts.lib.logger import get_logger

log = get_logger(__name__)


def save_baseline(path: Path, baseline: dict[str, Any]) -> None:
    """Atomic write: temp file in the same dir, then os.replace.

    A crash mid-write otherwise leaves a truncated JSON baseline that would
    corrupt the next scan's diff. os.replace is atomic on POSIX and Windows
    when source and destination share a filesystem, which the same-dir temp
    guarantees.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".baseline.", suffix=".json.tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def load_baseline(path: Path) -> Optional[dict[str, Any]]:
    """Load a baseline JSON file. Returns None if missing or unreadable.

    Corrupt / truncated JSON must not crash the scan or notify path — treat
    as no baseline (every finding will be tagged NEW on the next diff).
    """
    path = Path(path)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
        log.warning("baseline at %s unreadable (%s); treating as absent", path, e)
        return None


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
    # Iterate the union of prior/current paths so a manifest that disappeared
    # between scans (root removed, target deleted) also fires — dropping a
    # manifest without replacement is exactly the unauthorized change this
    # function is meant to catch, not just hash drift on a surviving manifest.
    for path in set(current_hashes) | set(prior_hashes):
        in_current = path in current_hashes
        in_prior = path in prior_hashes
        if in_prior and not in_current:
            if prior_finding_count is not None and current_finding_count <= prior_finding_count:
                alarms.append(
                    f"Baseline diff: {path} manifest removed since last scan "
                    f"(was {prior_hashes[path][:8]}...) without new findings"
                )
            continue
        if in_current and in_prior:
            prior_hash = prior_hashes[path]
            current_hash = current_hashes[path]
            if prior_hash != current_hash:
                if prior_finding_count is not None and current_finding_count <= prior_finding_count:
                    alarms.append(
                        f"Baseline diff: {path} hash changed "
                        f"({prior_hash[:8]}... → {current_hash[:8]}...) "
                        f"without new findings"
                    )
    return alarms

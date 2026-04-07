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

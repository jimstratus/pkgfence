"""Append-only audit log via per-run JSONL files.

Critic gap fix: shared append to a single file races on Windows where
O_APPEND atomicity is not guaranteed for records >PIPE_BUF. Per-run
files sidestep the race entirely. Aggregate at query time.

File layout: state/audit.jsonl.d/<run-id>.jsonl
"""
import json
from pathlib import Path
from typing import Any


def append_audit_record(state_dir: Path, run_id: str, record: dict[str, Any]) -> None:
    """Append a JSON record to the run's audit log file.

    Args:
        state_dir: pkgfence state directory (parent of audit.jsonl.d/)
        run_id: unique identifier for this scan run (e.g., timestamp + uuid suffix)
        record: dict to serialize as one JSONL line
    """
    audit_dir = Path(state_dir) / "audit.jsonl.d"
    audit_dir.mkdir(parents=True, exist_ok=True)
    file_path = audit_dir / f"{run_id}.jsonl"
    line = json.dumps(record, separators=(",", ":")) + "\n"
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(line)

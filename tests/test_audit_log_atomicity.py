"""Audit log atomicity test (critic gap M3 / shared-append race avoidance)."""
import json
import multiprocessing as mp
from pathlib import Path
from scripts.lib.audit_log import append_audit_record


def _writer_proc(state_dir, run_id, n):
    for i in range(n):
        append_audit_record(state_dir, run_id, {"i": i, "data": "x" * 1000})


def test_concurrent_appends_no_interleave(tmp_state):
    procs = [
        mp.Process(target=_writer_proc, args=(tmp_state, f"run-{p}", 50))
        for p in range(4)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join()

    # Per-run files (not shared append) means no interleaving by construction
    audit_dir = tmp_state / "audit.jsonl.d"
    files = list(audit_dir.glob("*.jsonl"))
    assert len(files) == 4
    for f in files:
        for line in f.read_text().splitlines():
            json.loads(line)  # must parse - no interleaved partial records


def test_append_audit_record_creates_dir(tmp_path):
    """audit.jsonl.d/ directory is created if missing."""
    state_dir = tmp_path / "newstate"
    state_dir.mkdir()
    append_audit_record(state_dir, "test-run", {"key": "value"})
    assert (state_dir / "audit.jsonl.d" / "test-run.jsonl").exists()


def test_append_audit_record_appends_not_overwrites(tmp_state):
    """Multiple appends to the same run_id accumulate as JSONL lines."""
    append_audit_record(tmp_state, "run-1", {"line": 1})
    append_audit_record(tmp_state, "run-1", {"line": 2})
    append_audit_record(tmp_state, "run-1", {"line": 3})
    file_path = tmp_state / "audit.jsonl.d" / "run-1.jsonl"
    lines = file_path.read_text().strip().splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["line"] == 1
    assert json.loads(lines[2])["line"] == 3

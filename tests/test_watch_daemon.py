"""Tests for scripts/watch_daemon.py — KEV watch cycle + CLI."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts.watch_daemon import (
    DEFAULT_STATE_DIR,
    _collect_feed_ids,
    _log_new_entries,
    _watch_kev,
    main,
    run_watch,
)


def test_collect_feed_ids_returns_copy_of_known_set():
    client = MagicMock()
    client._ensure_loaded.return_value = True
    live = {"CVE-2024-1", "CVE-2024-2"}
    client._known_set = live
    got = _collect_feed_ids(client)
    assert got == live
    got.add("CVE-2099-99999")
    assert "CVE-2099-99999" not in client._known_set


def test_collect_feed_ids_empty_when_load_fails():
    client = MagicMock()
    client._ensure_loaded.return_value = False
    assert _collect_feed_ids(client) == set()


def test_collect_feed_ids_falls_back_to_scores_keys():
    client = MagicMock(spec=["_ensure_loaded", "_scores"])
    client._ensure_loaded.return_value = True
    client._scores = {"CVE-2025-1": 0.9, "CVE-2025-2": 0.1}
    assert _collect_feed_ids(client) == {"CVE-2025-1", "CVE-2025-2"}


def test_collect_feed_ids_swallows_client_errors():
    client = MagicMock()
    client._ensure_loaded.side_effect = RuntimeError("boom")
    assert _collect_feed_ids(client) == set()


def test_log_new_entries_appends_jsonl_sorted_numerically(tmp_path):
    _log_new_entries(tmp_path, "kev", {"CVE-2025-10000", "CVE-2025-9999"})
    lines = (tmp_path / "watch-log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    ids = [json.loads(line)["id"] for line in lines]
    # Numeric sort: 9999 before 10000 (lexicographic would reverse them).
    assert ids == ["CVE-2025-9999", "CVE-2025-10000"]
    assert all(json.loads(line)["feed"] == "kev" for line in lines)


def test_watch_kev_first_cycle_logs_all_and_persists_cursor(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    fake_ids = {"CVE-2024-1", "CVE-2025-10000"}

    with patch("scripts.watch_daemon.KEVClient") as MockKEV:
        client = MagicMock()
        client._ensure_loaded.return_value = True
        client._known_set = fake_ids
        MockKEV.return_value = client
        n = _watch_kev(state)

    assert n == 2
    cursors = json.loads((state / "watch-cursors.json").read_text(encoding="utf-8"))
    assert set(cursors["kev"]["seen_ids"]) == fake_ids
    assert cursors["kev"]["total_known"] == 2
    log_lines = (state / "watch-log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(log_lines) == 2


def test_watch_kev_second_cycle_reports_only_new(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "watch-cursors.json").write_text(
        json.dumps({"kev": {"seen_ids": ["CVE-2024-1"], "total_known": 1}}),
        encoding="utf-8",
    )

    with patch("scripts.watch_daemon.KEVClient") as MockKEV:
        client = MagicMock()
        client._ensure_loaded.return_value = True
        client._known_set = {"CVE-2024-1", "CVE-2024-2"}
        MockKEV.return_value = client
        n = _watch_kev(state)

    assert n == 1
    log_lines = (state / "watch-log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(log_lines) == 1
    assert json.loads(log_lines[0])["id"] == "CVE-2024-2"


def test_watch_kev_empty_feed_skips_without_writing_cursor(tmp_path):
    state = tmp_path / "state"
    state.mkdir()

    with patch("scripts.watch_daemon.KEVClient") as MockKEV:
        client = MagicMock()
        client._ensure_loaded.return_value = False
        MockKEV.return_value = client
        n = _watch_kev(state)

    assert n == 0
    assert not (state / "watch-cursors.json").exists()
    assert not (state / "watch-log.jsonl").exists()


def test_run_watch_once_completes_single_cycle(tmp_path):
    with patch("scripts.watch_daemon._watch_kev", return_value=0) as watch:
        with patch("scripts.watch_daemon.time.sleep") as sleep:
            run_watch(tmp_path, interval=999, once=True)
    watch.assert_called_once_with(tmp_path)
    sleep.assert_not_called()


def test_main_passes_path_state_default():
    """Default --state (no CLI override) must already be a Path."""
    with patch("scripts.watch_daemon.run_watch") as run:
        with patch("sys.argv", ["pkgfence-watch", "--once"]):
            main()
    run.assert_called_once()
    state_arg = run.call_args.args[0]
    assert isinstance(state_arg, Path)
    assert state_arg == DEFAULT_STATE_DIR
    assert run.call_args.kwargs["once"] is True

"""Tests for watch cursor persistence and new-ID detection."""
from scripts.lib.watch_cursors import (
    load_cursors, save_cursors, find_new_ids, _id_sort_key,
)


def test_id_sort_key_orders_numeric_suffix_correctly():
    # Lexicographic order would put CVE-2025-9999 *after* CVE-2025-10000
    # ('9' > '1'). The numeric sort key must rank 10000 above 9999.
    assert _id_sort_key("CVE-2025-10000") > _id_sort_key("CVE-2025-9999")
    assert _id_sort_key("CVE-2025-9001") > _id_sort_key("CVE-2025-1000")


def test_find_new_ids_numeric_threshold():
    # Cursor at a 4-digit ID must still surface 5-digit IDs added later.
    current = {"CVE-2025-9999", "CVE-2025-10000", "CVE-2025-10001"}
    cursors = {"kev": {"last_id": "CVE-2025-9999"}}
    new = find_new_ids(current, "kev", cursors)
    assert new == {"CVE-2025-10000", "CVE-2025-10001"}


def test_find_new_ids_no_cursor_returns_all():
    current = {"CVE-2025-1", "CVE-2025-2"}
    assert find_new_ids(current, "kev", {}) == current


def test_save_and_load_cursors_roundtrip(tmp_path):
    p = tmp_path / "cursors.json"
    save_cursors(p, {"kev": {"last_id": "CVE-2025-10000", "total_known": 1}})
    loaded = load_cursors(p)
    assert loaded["kev"]["last_id"] == "CVE-2025-10000"


def test_load_cursors_missing_file_returns_empty(tmp_path):
    assert load_cursors(tmp_path / "nope.json") == {}
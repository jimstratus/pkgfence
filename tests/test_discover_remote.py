"""Tests for remote L1 discovery (Phase 2 SSH mode)."""
from unittest.mock import MagicMock

from scripts.discover_remote import discover_remote_manifests


def test_discover_remote_emits_records_for_each_find_hit():
    """SSHRunner.run('find ...') returns newline-delimited paths; we yield
    one RemoteManifest per path with ecosystem derived from filename."""
    runner = MagicMock()
    runner.host = "dev-host-1.example"
    # First call = find; subsequent calls = sha256sum per file
    runner.run.side_effect = [
        "/var/www/app1/package-lock.json\n/var/www/app2/requirements.txt\n",
        "deadbeef  /var/www/app1/package-lock.json\n",
        "cafef00d  /var/www/app2/requirements.txt\n",
    ]
    target = {
        "name": "dev-host-1",
        "host": "dev-host-1.example",
        "user": "devuser",
        "tier": 2,
        "discover_paths": ["/var/www"],
    }
    records = list(discover_remote_manifests(target, runner))
    assert len(records) == 2
    assert records[0]["target"] == "dev-host-1"
    assert records[0]["host"] == "dev-host-1.example"
    assert records[0]["path"] == "/var/www/app1/package-lock.json"
    assert records[0]["ecosystem"] == "npm"
    assert records[0]["manifest_hash"] == "deadbeef"
    assert records[0]["tier"] == 2
    assert records[1]["ecosystem"] == "python"


def test_discover_remote_empty_when_no_discover_paths():
    """No discover_paths -> empty iterator, never invokes runner."""
    runner = MagicMock()
    target = {"name": "x", "host": "h", "user": "u", "tier": 1}
    records = list(discover_remote_manifests(target, runner))
    assert records == []
    runner.run.assert_not_called()

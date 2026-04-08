"""Tests for remote L1 discovery (Phase 2 SSH mode)."""
from unittest.mock import MagicMock

from scripts.discover_remote import discover_remote_manifests, discover_remote_safely
from scripts.lib.ssh_runner import SSHUnreachableError


def test_discover_remote_emits_records_for_each_find_hit():
    """SSHRunner.run('find ...') returns newline-delimited paths; we yield
    one RemoteManifest per path with ecosystem derived from filename."""
    runner = MagicMock()
    # First call = find; subsequent calls = sha256sum per file
    runner.run.side_effect = [
        "/var/www/app1/package-lock.json\n/var/www/app2/requirements.txt\n",
        "a" * 64 + "  /var/www/app1/package-lock.json\n",
        "b" * 64 + "  /var/www/app2/requirements.txt\n",
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
    assert records[0]["manifest_hash"] == "a" * 64
    assert records[0]["tier"] == 2
    assert records[1]["ecosystem"] == "python"

    # Verify the runner was actually called with the expected commands
    call_args_list = [call.args[0] for call in runner.run.call_args_list]
    assert len(call_args_list) == 3
    # First call: find with escaped parens
    assert call_args_list[0][0] == "find"
    assert "\\(" in call_args_list[0]
    # Subsequent calls: sha256sum with the discovered paths
    assert call_args_list[1] == ["sha256sum", "/var/www/app1/package-lock.json"]
    assert call_args_list[2] == ["sha256sum", "/var/www/app2/requirements.txt"]


def test_discover_remote_empty_when_no_discover_paths():
    """No discover_paths -> empty iterator, never invokes runner."""
    runner = MagicMock()
    target = {"name": "x", "host": "h", "user": "u", "tier": 1}
    records = list(discover_remote_manifests(target, runner))
    assert records == []
    runner.run.assert_not_called()


def test_build_find_command_escapes_parens_for_remote_shell():
    """The remote shell interprets unescaped `(` and `)` as subshell grouping.
    find's expression grouping requires them to be backslash-escaped so the
    shell passes literal parens to find(1)."""
    from scripts.discover_remote import _build_find_command
    cmd = _build_find_command(["/var/www"])
    # Parens must be present as escaped forms
    assert "\\(" in cmd
    assert "\\)" in cmd
    # Unescaped bare parens must NOT be in the argv
    assert "(" not in cmd
    assert ")" not in cmd
    # Structure sanity
    assert cmd[0] == "find"
    assert "/var/www" in cmd
    assert "-maxdepth" in cmd
    assert "-type" in cmd
    assert "-name" in cmd


def test_discover_remote_safely_converts_unreachable_to_scan_error_record():
    """When SSH is unreachable, yield a single SCAN_ERROR manifest record
    that downstream report generation can render as a failed target."""
    runner = MagicMock()
    runner.run.side_effect = SSHUnreachableError("dev-host-1 unreachable")
    target = {"name": "dev-host-1", "host": "h", "user": "u", "tier": 2,
              "discover_paths": ["/var/www"]}
    records = list(discover_remote_safely(target, runner))
    assert len(records) == 1
    assert records[0]["ecosystem"] == "SCAN_ERROR"
    assert records[0]["target"] == "dev-host-1"
    assert "unreachable" in records[0].get("error", "")


def test_discover_remote_safely_yields_partial_results_before_scan_error():
    """If SSHUnreachableError raises mid-iteration (e.g. after some sha256sum
    calls succeeded), discover_remote_safely yields the good records first
    and appends a SCAN_ERROR sentinel. Task 10 callers must handle this
    mixed-output case: SCAN_ERROR does NOT mean zero valid records.
    """
    runner = MagicMock()
    runner.run.side_effect = [
        "/var/www/app1/package-lock.json\n/var/www/app2/requirements.txt\n",
        "a" * 64 + "  /var/www/app1/package-lock.json\n",
        SSHUnreachableError("dropped mid-scan"),
    ]
    target = {"name": "dev-host-1", "host": "h", "user": "u", "tier": 2,
              "discover_paths": ["/var/www"]}
    records = list(discover_remote_safely(target, runner))
    # One good record, then a SCAN_ERROR sentinel
    assert len(records) == 2
    assert records[0]["ecosystem"] == "npm"
    assert records[0]["manifest_hash"] == "a" * 64
    assert records[1]["ecosystem"] == "SCAN_ERROR"
    assert "dropped mid-scan" in records[1]["error"]

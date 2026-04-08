"""Tests for remote L1 discovery (Phase 2 SSH mode)."""
from unittest.mock import MagicMock

from scripts.discover_remote import discover_remote_manifests


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

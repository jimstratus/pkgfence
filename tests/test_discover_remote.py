"""Tests for remote L1 discovery (Phase 2 SSH mode)."""
from unittest.mock import MagicMock

from scripts.discover_remote import discover_remote_manifests, discover_remote_safely
from scripts.lib.ssh_runner import SSHUnreachableError


def test_discover_remote_emits_records_for_each_find_hit():
    """SSHRunner.run('find ...') returns newline-delimited paths; we yield
    one RemoteManifest per path with ecosystem derived from filename.

    Issue #19.2: all manifests are hashed in a single batched sha256sum call
    (1 find + 1 sha256sum = 2 total runner.run calls regardless of N paths).
    """
    runner = MagicMock()
    # First call = find; second call = batched sha256sum for all paths
    runner.run.side_effect = [
        "/var/www/app1/package-lock.json\n/var/www/app2/requirements.txt\n",
        ("a" * 64) + "  /var/www/app1/package-lock.json\n"
        + ("b" * 64) + "  /var/www/app2/requirements.txt\n",
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
    assert records[1]["manifest_hash"] == "b" * 64

    # Verify the runner was called exactly twice: find + one batched sha256sum
    call_args_list = [call.args[0] for call in runner.run.call_args_list]
    assert len(call_args_list) == 2
    # First call: find with bare parens (SSHRunner quotes centrally)
    assert call_args_list[0][0] == "find"
    assert "(" in call_args_list[0]
    # Second call: batched sha256sum with both paths in one invocation
    assert call_args_list[1][0] == "sha256sum"
    assert "/var/www/app1/package-lock.json" in call_args_list[1]
    assert "/var/www/app2/requirements.txt" in call_args_list[1]


def test_discover_remote_empty_when_no_discover_paths():
    """No discover_paths -> empty iterator, never invokes runner."""
    runner = MagicMock()
    target = {"name": "x", "host": "h", "user": "u", "tier": 1}
    records = list(discover_remote_manifests(target, runner))
    assert records == []
    runner.run.assert_not_called()


def test_build_find_command_uses_bare_parens_for_central_quoting():
    """SSHRunner shlex-quotes every argument centrally, so find's grouping
    operators must be BARE parens — pre-escaped \\( would reach find as a
    literal backslash-paren after quoting (issue #7)."""
    from scripts.discover_remote import _build_find_command
    cmd = _build_find_command(["/var/www"])
    assert "(" in cmd
    assert ")" in cmd
    assert "\\(" not in cmd
    assert "\\)" not in cmd
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


def test_discover_remote_safely_yields_scan_error_when_hash_phase_unreachable():
    """If SSHUnreachableError raises during the sha256sum phase, no manifests
    from that target are yielded — only a SCAN_ERROR sentinel.

    With batched hashing (issue #19.2), all sha256sum calls are made eagerly
    before any yield. An SSHUnreachableError during hashing therefore prevents
    all records from that target, unlike the old per-path approach where some
    records could have been yielded before the error. discover_remote_safely
    converts the exception to a single SCAN_ERROR record.

    NOTE: partial results across different *targets* are still possible at the
    scan_command level (each target is a separate discover_remote_safely call).
    """
    runner = MagicMock()
    runner.run.side_effect = [
        "/var/www/app1/package-lock.json\n/var/www/app2/requirements.txt\n",
        SSHUnreachableError("dropped mid-scan"),  # sha256sum batch call fails
    ]
    target = {"name": "dev-host-1", "host": "h", "user": "u", "tier": 2,
              "discover_paths": ["/var/www"]}
    records = list(discover_remote_safely(target, runner))
    # No good records — hash phase failed before any yield; just SCAN_ERROR
    assert len(records) == 1
    assert records[0]["ecosystem"] == "SCAN_ERROR"
    assert records[0]["target"] == "dev-host-1"
    assert "dropped mid-scan" in records[0]["error"]


def test_build_find_command_prunes_excluded_directories():
    """The find command must prune DEFAULT_EXCLUDES directories (node_modules,
    .git, .venv, etc.) so nested transitive lockfiles don't pollute the scan."""
    from scripts.discover_remote import _build_find_command
    from scripts.discover import DEFAULT_EXCLUDES
    cmd = _build_find_command(["/var/www"])
    # Every name in DEFAULT_EXCLUDES should appear in the argv
    for exc in DEFAULT_EXCLUDES:
        assert exc in cmd, f"{exc!r} missing from find argv"
    # -prune must be present
    assert "-prune" in cmd
    # Explicit -print must be present (without it, pruned dirs get printed)
    assert "-print" in cmd
    # Bare parens must still be present (quoting happens in SSHRunner)
    assert "(" in cmd
    assert ")" in cmd


def test_discovery_hashes_all_manifests_in_one_roundtrip():
    """Issue #19.2: N discovered manifests = 1 find + 1 sha256sum call."""
    runner = MagicMock()
    runner.run.side_effect = [
        "/var/www/a/package-lock.json\n/var/www/b/composer.lock\n",  # find
        ("a" * 64) + "  /var/www/a/package-lock.json\n"
        + ("b" * 64) + "  /var/www/b/composer.lock\n",               # sha256sum
    ]
    target = {"name": "bespin", "host": "h", "tier": 1,
              "discover_paths": ["/var/www"]}
    manifests = list(discover_remote_manifests(target, runner))
    assert len(manifests) == 2
    assert runner.run.call_count == 2
    assert runner.run.call_args_list[1].args[0][0] == "sha256sum"
    assert manifests[0]["manifest_hash"] == "a" * 64

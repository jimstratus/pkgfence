"""Tests for `pkgfence ssh precheck <name>` (Phase 2)."""
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.ssh_precheck import main
from scripts.lib.ssh_runner import SSHUnreachableError


def _init_registry_with_ssh(path: Path, name: str = "dev-host-1") -> None:
    path.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        f"  - name: {name}\n"
        "    host: 192.0.2.10\n"
        "    user: devuser\n"
        "    tier: 2\n"
        "    discover_paths: ['/var/www']\n"
        "github: []\n"
    )


def test_precheck_success(tmp_path, capsys):
    reg = tmp_path / "registry.yaml"
    _init_registry_with_ssh(reg)

    def fake_run(self, command):
        if command[0] == "osv-scanner":
            return "osv-scanner version: 2.3.3\n"
        if command[0] == "stat":
            return "  File: /var/www\n  Size: 4096\n"
        return ""

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_run):
        rc = main(["--registry", str(reg), "dev-host-1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dev-host-1" in out
    assert "osv-scanner" in out
    assert "2.3.3" in out


def test_precheck_target_not_in_registry(tmp_path):
    reg = tmp_path / "registry.yaml"
    _init_registry_with_ssh(reg)
    rc = main(["--registry", str(reg), "nonexistent"])
    assert rc == 3


def test_precheck_unreachable_host_exits_nonzero(tmp_path):
    reg = tmp_path / "registry.yaml"
    _init_registry_with_ssh(reg)

    def fake_run(self, command):
        raise SSHUnreachableError("unreachable")

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_run):
        rc = main(["--registry", str(reg), "dev-host-1"])
    assert rc == 2


def test_precheck_discover_path_missing_returns_nonzero(tmp_path, capsys):
    """A discover_path that doesn't exist on the remote must cause precheck
    to exit 2 — not silently pass. stat of a missing path returns empty
    stdout on the remote, which is what we detect here."""
    reg = tmp_path / "registry.yaml"
    _init_registry_with_ssh(reg)

    def fake_run(self, command):
        if command[0] == "osv-scanner":
            return "osv-scanner version: 2.3.3\n"
        if command[0] == "stat":
            # stat of a missing path: SSHRunner.run returns empty stdout
            # because stat's stderr is discarded and rc != 255
            return ""
        return ""

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_run):
        rc = main(["--registry", str(reg), "dev-host-1"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "discover_path" in err
    assert "/var/www" in err


def test_precheck_multiple_discover_paths_reports_all_results(tmp_path, capsys):
    """With multiple discover_paths, precheck reports the status of all
    paths (OK or FAIL) before returning, not just the first failure."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: dev-host-1\n"
        "    host: 192.0.2.10\n"
        "    user: devuser\n"
        "    tier: 2\n"
        "    discover_paths: ['/var/www', '/opt', '/srv']\n"
        "github: []\n"
    )

    call_log: list = []

    def fake_run(self, command):
        call_log.append(command)
        if command[0] == "osv-scanner":
            return "osv-scanner version: 2.3.3\n"
        if command[0] == "stat":
            path = command[1]
            # /var/www exists, /opt does not, /srv exists
            if path == "/opt":
                return ""
            return f"File: {path}\n  Size: 4096\n"
        return ""

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_run):
        rc = main(["--registry", str(reg), "dev-host-1"])
    # One of three failed → exit 2
    assert rc == 2
    # All three paths were checked (not just up to first failure)
    stat_calls = [c for c in call_log if c[0] == "stat"]
    assert len(stat_calls) == 3
    assert ["stat", "/var/www"] in stat_calls
    assert ["stat", "/opt"] in stat_calls
    assert ["stat", "/srv"] in stat_calls

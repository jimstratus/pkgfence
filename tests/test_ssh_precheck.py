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
        if command[0] == "ls":
            return "/var/www\n"
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

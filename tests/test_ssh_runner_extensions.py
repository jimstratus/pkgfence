"""Tests for Phase 2 extensions to SSHRunner: key_file, scanner_user, use_sudo.

These must preserve S1 (no silent fallback) and S3 (command allowlist)."""
import pytest
from unittest.mock import patch, MagicMock

from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError


def test_ssh_runner_accepts_key_file_and_passes_i_flag():
    """When key_file is set, the ssh subprocess receives -i <path>."""
    runner = SSHRunner(host="h.example", user="u", key_file="/tmp/k")
    with patch("scripts.lib.ssh_runner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/tmp", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "-i" in args
    assert args[args.index("-i") + 1] == "/tmp/k"


def test_ssh_runner_without_key_file_omits_i_flag():
    """When key_file is None/omitted, no -i flag is added (fall back to ~/.ssh/config)."""
    runner = SSHRunner(host="h.example", user="u")
    with patch("scripts.lib.ssh_runner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/tmp", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "-i" not in args


def test_ssh_runner_use_sudo_prefixes_command_with_sudo_n():
    """use_sudo=True prefixes the remote command with 'sudo -n'.
    -n is required: never prompt for password. If sudo lacks nopasswd, fail fast."""
    runner = SSHRunner(host="h.example", user="u", use_sudo=True)
    with patch("scripts.lib.ssh_runner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["osv-scanner", "-L", "/tmp/lock.json", "--format", "json"])
    args = mock_run.call_args[0][0]
    # Use index-based search instead of positional arithmetic —
    # the position of 'sudo' shifts depending on whether key_file is set.
    assert "sudo" in args
    sudo_idx = args.index("sudo")
    assert args[sudo_idx + 1] == "-n"
    assert args[sudo_idx + 2] == "osv-scanner"


def test_ssh_runner_use_sudo_still_enforces_allowlist():
    """S3 preserved: use_sudo does not let disallowed commands through."""
    runner = SSHRunner(host="h.example", user="u", use_sudo=True)
    with pytest.raises(ValueError, match="not in SSH allowlist"):
        runner.run(["mkdir", "/tmp/foo"])


def test_ssh_runner_default_no_sudo_no_prefix():
    """Default (use_sudo=False): no sudo prefix."""
    runner = SSHRunner(host="h.example", user="u")
    with patch("scripts.lib.ssh_runner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/tmp", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "sudo" not in args


def test_ssh_runner_uses_p_flag_when_port_set():
    """When port is set, the ssh subprocess receives -p <port>."""
    runner = SSHRunner(host="mars.example", user="scanuser", port=2222)
    with patch("scripts.lib.ssh_runner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/var/www", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "-p" in args
    assert args[args.index("-p") + 1] == "2222"


def test_ssh_runner_omits_p_flag_when_port_not_set():
    """When port is None/omitted, no -p flag is added (defaults to ssh's port 22)."""
    runner = SSHRunner(host="mars.example", user="scanuser")
    with patch("scripts.lib.ssh_runner.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/var/www", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "-p" not in args

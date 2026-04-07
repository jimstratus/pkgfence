"""Tests for Phase 2 extensions to SSHRunner: key_file, scanner_user, use_sudo.

These must preserve S1 (no silent fallback) and S3 (command allowlist)."""
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

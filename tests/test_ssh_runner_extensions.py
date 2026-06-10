"""Tests for Phase 2 extensions to SSHRunner: key_file, scanner_user, use_sudo.

These must preserve S1 (no silent fallback) and S3 (command allowlist)."""
import os
import pytest
import shlex
from unittest.mock import patch, MagicMock

from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError, ALLOWED_COMMANDS


def test_ssh_runner_accepts_key_file_and_passes_i_flag():
    """When key_file is set, the ssh subprocess receives -i <path>."""
    runner = SSHRunner(host="h.example", user="u", key_file="/tmp/k")
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/tmp", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "-i" in args
    assert args[args.index("-i") + 1] == "/tmp/k"


def test_ssh_runner_without_key_file_omits_i_flag():
    """When key_file is None/omitted, no -i flag is added (fall back to ~/.ssh/config)."""
    runner = SSHRunner(host="h.example", user="u")
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/tmp", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "-i" not in args


def test_ssh_runner_use_sudo_prefixes_command_with_sudo_n():
    """use_sudo=True prefixes the remote command with 'sudo -n'.
    -n is required: never prompt for password. If sudo lacks nopasswd, fail fast."""
    runner = SSHRunner(host="h.example", user="u", use_sudo=True)
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["osv-scanner", "-L", "/tmp/lock.json", "--format", "json"])
    args = mock_run.call_args[0][0]
    # The remote command is one shlex-quoted string (last ssh arg);
    # split it back to recover the intended remote argv.
    remote_argv = shlex.split(args[-1])
    assert remote_argv[0] == "sudo"
    assert remote_argv[1] == "-n"
    assert remote_argv[2] == "osv-scanner"


def test_ssh_runner_use_sudo_still_enforces_allowlist():
    """S3 preserved: use_sudo does not let disallowed commands through."""
    runner = SSHRunner(host="h.example", user="u", use_sudo=True)
    with pytest.raises(ValueError, match="not in SSH allowlist"):
        runner.run(["mkdir", "/tmp/foo"])


def test_ssh_runner_default_no_sudo_no_prefix():
    """Default (use_sudo=False): no sudo prefix."""
    runner = SSHRunner(host="h.example", user="u")
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/tmp", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "sudo" not in args


def test_ssh_runner_uses_p_flag_when_port_set():
    """When port is set, the ssh subprocess receives -p <port>."""
    runner = SSHRunner(host="mars.example", user="scanuser", port=2222)
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/var/www", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "-p" in args
    assert args[args.index("-p") + 1] == "2222"


def test_ssh_runner_omits_p_flag_when_port_not_set():
    """When port is None/omitted, no -p flag is added (defaults to ssh's port 22)."""
    runner = SSHRunner(host="mars.example", user="scanuser")
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["find", "/var/www", "-name", "x"])
    args = mock_run.call_args[0][0]
    assert "-p" not in args


def test_ssh_runner_decodes_stdout_as_utf8():
    """SSHRunner.run() must decode stdout as UTF-8 with errors='replace',
    not the Windows cp1252 default. Real osv-scanner JSON output contains
    UTF-8 bytes from international package names and CVE descriptions.

    Without this fix, on Windows, _readerthread dies with UnicodeDecodeError
    and result.stdout becomes None, breaking parse_osv_output downstream.
    """
    runner = SSHRunner(host="h.example", user="u")
    # Build a fake stdout containing a UTF-8 byte that cp1252 cannot decode
    # (the same byte that crashed mars: 0x81 is undefined in cp1252).
    # When passed through encoding='utf-8' errors='replace', it becomes U+FFFD.
    utf8_payload = "before \ufffd after\n"
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout=utf8_payload, stderr="",
        )
        result = runner.run(["find", "/tmp", "-name", "x"])
    # The call must have requested utf-8 encoding with errors='replace'
    kwargs = mock_run.call_args.kwargs
    assert kwargs.get("encoding") == "utf-8"
    assert kwargs.get("errors") == "replace"
    assert result == utf8_payload


def test_ssh_runner_subprocess_call_includes_encoding_kwargs():
    """Defensive: every subprocess.run call from SSHRunner must pin
    encoding='utf-8' and errors='replace' so scanner output containing
    UTF-8 bytes does not crash the Windows cp1252 default decoder."""
    runner = SSHRunner(host="h.example", user="u", port=22)
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        runner.run(["sha256sum", "/etc/hostname"])
    kwargs = mock_run.call_args.kwargs
    assert kwargs.get("text") is True
    assert kwargs.get("encoding") == "utf-8"
    assert kwargs.get("errors") == "replace"
    assert kwargs.get("capture_output") is True


# ---------------------------------------------------------------------------
# Phase 2.5 Task 1: run_with_rc() and basename allowlist
# ---------------------------------------------------------------------------

def test_run_with_rc_returns_stdout_and_returncode():
    """run_with_rc() returns (stdout, returncode) tuple on success."""
    runner = SSHRunner(host="h.example", user="u")
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="found\n", stderr="")
        result = runner.run_with_rc(["stat", "/usr/local/bin/osv-scanner"])
    assert result == ("found\n", 0)


def test_run_with_rc_returns_nonzero_on_missing_file():
    """run_with_rc() returns (stdout, 1) when command exits with rc=1 (file not found)."""
    runner = SSHRunner(host="h.example", user="u")
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="No such file")
        result = runner.run_with_rc(["stat", "/nonexistent/path"])
    assert result == ("", 1)


def test_run_with_rc_raises_on_ssh_failure():
    """run_with_rc() raises SSHUnreachableError when rc=255 (SSH connect failure)."""
    runner = SSHRunner(host="h.example", user="u")
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=255, stdout="", stderr="Connection refused")
        with pytest.raises(SSHUnreachableError):
            runner.run_with_rc(["stat", "/tmp/x"])


def test_run_with_rc_rejects_disallowed_command():
    """run_with_rc() raises ValueError for commands not in the allowlist."""
    runner = SSHRunner(host="h.example", user="u")
    with pytest.raises(ValueError, match="not in SSH allowlist"):
        runner.run_with_rc(["curl", "http://evil.example"])


def test_allowlist_accepts_absolute_path_with_allowed_basename():
    """Absolute path /usr/local/bin/osv-scanner passes because basename 'osv-scanner' is allowed."""
    runner = SSHRunner(host="h.example", user="u")
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
        # Should NOT raise ValueError
        runner.run(["/usr/local/bin/osv-scanner", "--version"])
    mock_run.assert_called_once()


def test_allowlist_rejects_absolute_path_with_disallowed_basename():
    """Absolute path /usr/bin/curl fails because basename 'curl' is not in the allowlist."""
    runner = SSHRunner(host="h.example", user="u")
    with pytest.raises(ValueError, match="not in SSH allowlist"):
        runner.run(["/usr/bin/curl", "http://evil.example"])


# ---------------------------------------------------------------------------
# Task 19: SSH ControlMaster connection reuse (POSIX-only)
# ---------------------------------------------------------------------------

def test_control_master_enabled_on_posix():
    runner = SSHRunner(host="example.invalid", user="nobody")
    ssh_cmd = runner._build_ssh_cmd(["ls", "/tmp"])
    if os.name == "posix":
        assert "ControlMaster=auto" in ssh_cmd
    else:
        assert "ControlMaster=auto" not in ssh_cmd

"""SSH command runner with strict allowlist and no-local-fallback safety.

S1 invariant: SSH unreachable raises SSHUnreachableError. Never falls back
to running the command locally. Never silently swallows the error.
S3 invariant: Only commands in the allowlist may run on remote hosts, and
every argument is shell-quoted before reaching the remote login shell.
"""
import subprocess
import shlex
from pathlib import PurePosixPath
from typing import List

from scripts.lib.proc import run_capture


class SSHUnreachableError(Exception):
    """Raised when an SSH target is unreachable. NEVER caught and converted
    to a silent local fallback. NEVER suppressed."""


# S3: command allowlist for SSH targets — only read-syscall and scanner commands
ALLOWED_COMMANDS = frozenset({
    "find", "cat", "sha256sum", "ls", "stat",
    "osv-scanner", "trivy", "zizmor",
})


class SSHRunner:
    def __init__(
        self,
        host: str,
        user: str,
        key_file: str | None = None,
        use_sudo: bool = False,
        port: int | None = None,
    ):
        self.host = host
        self.user = user
        self.key_file = key_file
        self.use_sudo = use_sudo
        self.port = port

    # Control characters that can never appear in a legitimate remote argv
    # element. Newlines would also corrupt line-oriented output parsing.
    _FORBIDDEN_ARG_CHARS = ("\x00", "\n", "\r")

    def _check_allowlist(self, command: List[str]) -> None:
        """Raise ValueError if command is empty, its basename is not in the
        allowlist, or any argument contains a forbidden control character."""
        if not command:
            raise ValueError("Empty command")
        basename = PurePosixPath(command[0]).name
        if basename not in ALLOWED_COMMANDS:
            raise ValueError(
                f"Command {command[0]!r} not in SSH allowlist {sorted(ALLOWED_COMMANDS)}"
            )
        for arg in command:
            if any(c in arg for c in self._FORBIDDEN_ARG_CHARS):
                raise ValueError(
                    f"Forbidden control character in SSH argument: {arg!r}"
                )

    def _build_ssh_cmd(self, command: List[str]) -> List[str]:
        """Build the full ssh argv. The remote command is passed as ONE
        pre-quoted string: ssh space-joins its trailing args and the remote
        login shell re-parses them, so every element MUST be shlex-quoted
        here (S3 — see issue #7). Callers pass bare '(' ')' for find."""
        if self.use_sudo:
            # `-n` = never prompt; if sudo lacks NOPASSWD for this cmd, fail fast
            command = ["sudo", "-n"] + command
        remote_cmd = " ".join(shlex.quote(arg) for arg in command)
        ssh_cmd = ["ssh", "-o", "ConnectTimeout=10",
                   "-o", "BatchMode=yes"]  # never prompt for password
        if self.port is not None:
            ssh_cmd += ["-p", str(self.port)]
        if self.key_file:
            # IdentitiesOnly avoids ssh-agent key fanout (CLAUDE.md gotcha)
            ssh_cmd += ["-i", self.key_file, "-o", "IdentitiesOnly=yes"]
        ssh_cmd += [f"{self.user}@{self.host}", remote_cmd]
        return ssh_cmd

    def _run(self, command: List[str]) -> "subprocess.CompletedProcess[str]":
        """Shared body of run()/run_with_rc(): allowlist, quote, execute,
        translate connect failures to SSHUnreachableError (S1)."""
        self._check_allowlist(command)
        ssh_cmd = self._build_ssh_cmd(command)
        try:
            result = run_capture(ssh_cmd, timeout=300)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            raise SSHUnreachableError(f"SSH to {self.host} failed: {e}") from e
        if result.returncode == 255:  # SSH connect failure
            raise SSHUnreachableError(
                f"SSH to {self.host} unreachable: {result.stderr.strip()}"
            )
        return result

    def run(self, command: List[str]) -> str:
        """Run a command on the remote via SSH. Raises SSHUnreachableError if
        the host is unreachable. Raises ValueError if the command is not allowed."""
        return self._run(command).stdout

    def run_with_rc(self, command: List[str]) -> tuple[str, int]:
        """Like run(), but returns (stdout, returncode) so callers can
        distinguish success (0) from command-level failures (e.g. rc=1
        for file-not-found in stat)."""
        result = self._run(command)
        return result.stdout, result.returncode

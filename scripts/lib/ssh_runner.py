"""SSH command runner with strict allowlist and no-local-fallback safety.

S1 invariant: SSH unreachable raises SSHUnreachableError. Never falls back
to running the command locally. Never silently swallows the error.
S3 invariant: Only commands in the allowlist may run on remote hosts.
"""
import subprocess
from pathlib import PurePosixPath
from typing import List


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

    def _check_allowlist(self, command: List[str]) -> None:
        """Raise ValueError if command is empty or its basename is not in the allowlist."""
        if not command:
            raise ValueError("Empty command")
        basename = PurePosixPath(command[0]).name
        if basename not in ALLOWED_COMMANDS:
            raise ValueError(
                f"Command {command[0]!r} not in SSH allowlist {sorted(ALLOWED_COMMANDS)}"
            )

    def _build_ssh_cmd(self, command: List[str]) -> List[str]:
        """Build the full ssh argv list for the given remote command."""
        if self.use_sudo:
            # `-n` = never prompt; if sudo lacks NOPASSWD for this cmd, fail fast
            command = ["sudo", "-n"] + command
        ssh_cmd = ["ssh", "-o", "ConnectTimeout=10",
                   "-o", "BatchMode=yes"]  # never prompt for password
        if self.port is not None:
            ssh_cmd += ["-p", str(self.port)]
        if self.key_file:
            ssh_cmd += ["-i", self.key_file]
        ssh_cmd += [f"{self.user}@{self.host}"] + command
        return ssh_cmd

    def run(self, command: List[str]) -> str:
        """Run a command on the remote via SSH. Raises SSHUnreachableError if
        the host is unreachable. Raises ValueError if the command is not allowed."""
        self._check_allowlist(command)
        ssh_cmd = self._build_ssh_cmd(command)
        try:
            result = subprocess.run(
                ssh_cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=300, check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            raise SSHUnreachableError(f"SSH to {self.host} failed: {e}") from e
        if result.returncode == 255:  # SSH connect failure
            raise SSHUnreachableError(
                f"SSH to {self.host} unreachable: {result.stderr.strip()}"
            )
        return result.stdout

    def run_with_rc(self, command: List[str]) -> tuple[str, int]:
        """Run a command on the remote via SSH, returning (stdout, returncode).

        Same allowlist enforcement and SSHUnreachableError semantics as run(),
        but exposes the exit code so callers can distinguish success (0) from
        command-level failures (e.g. rc=1 for file-not-found in stat)."""
        self._check_allowlist(command)
        ssh_cmd = self._build_ssh_cmd(command)
        try:
            result = subprocess.run(
                ssh_cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=300, check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            raise SSHUnreachableError(f"SSH to {self.host} failed: {e}") from e
        if result.returncode == 255:  # SSH connect failure
            raise SSHUnreachableError(
                f"SSH to {self.host} unreachable: {result.stderr.strip()}"
            )
        return result.stdout, result.returncode

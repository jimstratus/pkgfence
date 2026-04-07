"""SSH command runner with strict allowlist and no-local-fallback safety.

S1 invariant: SSH unreachable raises SSHUnreachableError. Never falls back
to running the command locally. Never silently swallows the error.
S3 invariant: Only commands in the allowlist may run on remote hosts.
"""
import subprocess
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
    def __init__(self, host: str, user: str, key_file: str | None = None):
        self.host = host
        self.user = user
        self.key_file = key_file

    def run(self, command: List[str]) -> str:
        """Run a command on the remote via SSH. Raises SSHUnreachableError if
        the host is unreachable. Raises ValueError if the command is not allowed."""
        if not command:
            raise ValueError("Empty command")
        if command[0] not in ALLOWED_COMMANDS:
            raise ValueError(
                f"Command {command[0]!r} not in SSH allowlist {sorted(ALLOWED_COMMANDS)}"
            )
        ssh_cmd = ["ssh", "-o", "ConnectTimeout=10",
                   "-o", "BatchMode=yes"]  # never prompt for password
        if self.key_file:
            ssh_cmd += ["-i", self.key_file]
        ssh_cmd += [f"{self.user}@{self.host}"] + command
        try:
            result = subprocess.run(
                ssh_cmd, capture_output=True, text=True, timeout=300, check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            raise SSHUnreachableError(f"SSH to {self.host} failed: {e}") from e
        if result.returncode == 255:  # SSH connect failure
            raise SSHUnreachableError(
                f"SSH to {self.host} unreachable: {result.stderr.strip()}"
            )
        return result.stdout

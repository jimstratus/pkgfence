# Safety Invariants

These invariants are load-bearing. If any test in `tests/test_safety_invariants.py`
fails, the skill is broken and must NOT be run until the test passes again.

## S1: No silent local fallback

When an SSH target is unreachable, `SSHRunner.run()` raises `SSHUnreachableError`.
It NEVER catches this and runs the command locally as a substitute. NEVER.

A silent local fallback would produce a clean report for a server that was
never actually scanned — the worst possible outcome.

**Test:** `test_no_silent_local_fallback_when_ssh_unreachable`
**Enforcement:** `scripts/lib/ssh_runner.py` has no local-fallback code path.

## S2: No package-manager install commands

`pkgfence` reads lockfiles; it never executes `npm install`, `pip install`,
`cargo install`, `gem install`, `bundle install`, `go install`, or any
equivalent. Not directly. Not via Docker. Not in any sandbox. Ever.

This is the Shai-Hulud-class attack vector. Postinstall scripts run as your
user, read your env, and in some failure modes nuke your home directory.
`pkgfence` exists *because* of this; it must never be the cause.

**Test:** `test_no_package_manager_install_anywhere_in_scripts`
**Enforcement:** static regex scan of all `scripts/**/*.py` on every test run.

## S3: SSH command allowlist

Commands run on remote SSH targets are limited to a fixed allowlist:
`find, cat, sha256sum, ls, stat, osv-scanner, trivy, zizmor`.

No `mkdir`, no `touch`, no `tee`, no `scp` writes, no `rm`, no `wget`,
no `curl`, no shell.

**Test:** `test_ssh_command_allowlist_refuses_disallowed_commands`
**Enforcement:** `ALLOWED_COMMANDS` frozenset in `scripts/lib/ssh_runner.py`.

# pkgfence SSH mode (Phase 2, v0.2.0)

Scan dependency manifests on remote hosts via SSH. `osv-scanner` runs
**on the remote host**; only its JSON output is sent back to the scanner
machine. Remote file contents (including source code and lockfiles)
never transit to the local machine — this is the S4 invariant.

## Architectural summary

    local machine                                   remote host (mars/bespin/dev-host-1)
    ┌─────────────┐                                 ┌──────────────────────────┐
    │ pkgfence    │ ssh find /var/www -name ...     │ find(1) outputs paths    │
    │ scan_remote │◄────────────────────────────────┤                          │
    │             │ ssh sha256sum <path>            │ sha256sum(1) outputs hex │
    │             │◄────────────────────────────────┤                          │
    │             │ ssh osv-scanner -L <path> ...   │ osv-scanner runs locally │
    │ (parses     │◄────────────────────────────────┤ on the host, emits JSON  │
    │  JSON only) │ JSON stdout                     │                          │
    └─────────────┘                                 └──────────────────────────┘

    No scp. No rsync. No cat-of-manifest. Only paths, hashes, and scanner JSON.

## Prerequisites on the remote host

Before running `pkgfence scan` with an SSH target, install osv-scanner
manually on each remote host. v0.2.0 ships with a `precheck` command but
not auto-bootstrap — bootstrap lands in v0.2.1.

### Installing osv-scanner (Linux)

osv-scanner must be installed to a directory that is in the remote host's
**non-interactive** SSH PATH. `~/.bashrc` is NOT read for non-interactive
SSH commands, so `~/.local/bin` alone will not work even if it's in your
interactive PATH. On Debian/Ubuntu the non-interactive PATH is typically
`/usr/local/bin:/usr/bin:/bin:/usr/games`, so installing to `/usr/local/bin`
via sudo is the simplest approach.

```bash
# On the remote host (e.g. as devuser or scanuser):
cd /tmp
curl -sSL -o osv-scanner \
  https://github.com/google/osv-scanner/releases/download/v2.3.3/osv-scanner_linux_amd64
curl -sSL -o osv-scanner_SHA256SUMS \
  https://github.com/google/osv-scanner/releases/download/v2.3.3/osv-scanner_SHA256SUMS

# Verify the hash before installing:
expected=$(grep 'osv-scanner_linux_amd64$' osv-scanner_SHA256SUMS | awk '{print $1}')
actual=$(sha256sum osv-scanner | awk '{print $1}')
[ "$expected" = "$actual" ] && echo "hash ok" || (echo "HASH MISMATCH" && exit 1)

# Install to /usr/local/bin (requires sudo — needed for the non-interactive PATH):
sudo install -m 755 osv-scanner /usr/local/bin/osv-scanner
rm osv-scanner osv-scanner_SHA256SUMS

# Verify the install is reachable via non-interactive SSH:
# (Run from your local machine, not from inside the remote shell.)
ssh <user>@<host> osv-scanner --version
# Expected: "osv-scanner version: 2.3.3" + osv-scalibr + commit lines
```

The non-interactive SSH test at the end is important: a plain `osv-scanner
--version` from inside an interactive SSH session may succeed even when the
non-interactive invocation fails (if you have `~/.local/bin` in your
interactive PATH but not in the default non-interactive PATH).

If you cannot install to `/usr/local/bin` (no sudo), see the `scanner_path`
workaround in the v0.2.1 roadmap — it will let you point pkgfence at an
absolute remote path. Until then, `/usr/local/bin` is the supported install
location.

### Verifying with precheck

Once osv-scanner is installed:

```bash
# From the local machine:
python -m scripts.ssh_precheck --registry state/registry.yaml dev-host-1
```

Expected output:

```
Precheck for dev-host-1 (devuser@192.0.2.10):
  [OK] osv-scanner present: osv-scanner version: 2.3.3
  [OK] discover_path exists: /var/www

All checks passed for dev-host-1
```

## Permission models

pkgfence supports two models for remote scanning. Pick the one that fits
the host's policy.

### Pattern A1 — ACL (default, recommended for production)

One-time setup as root on the remote host grants the scanner user read
access to the discover paths without sudo:

```bash
# Example for Plesk mars/bespin — grant scanuser read access to /var/www
sudo setfacl -R -m u:scanuser:rX /var/www
sudo setfacl -R -d -m u:scanuser:rX /var/www  # default ACL for new files
```

Registry entry:

```yaml
ssh:
  - name: mars
    host: mars.example
    user: scanuser
    key_file: ~/.ssh/scan-key
    tier: 1
    discover_paths:
      - /var/www
      - /var/www/vhosts
    acl_groups: [scanuser]
```

### Pattern A2 — sudo fallback

For hosts where ACL setup is impractical, grant the scanner user
passwordless sudo for `osv-scanner` only:

```bash
# /etc/sudoers.d/pkgfence-scan:
devuser ALL=(root) NOPASSWD: /home/devuser/.local/bin/osv-scanner
```

Registry entry adds `use_sudo: true`:

```yaml
ssh:
  - name: dev-host-1
    host: 192.0.2.10
    user: devuser
    key_file: ~/.ssh/lab-key
    tier: 2
    use_sudo: true
    discover_paths: ['/var/www']
```

pkgfence will invoke commands as `sudo -n osv-scanner ...`. The `-n`
flag ensures it **fails fast** if NOPASSWD is not configured — no
password prompt, no hang.

## Plesk-specific notes (mars, bespin)

- **Do NOT scan `/usr/local/psa/`** (Plesk control-panel internals).
  Leave it out of `discover_paths`.
- Plesk manages `/var/www/vhosts/<domain>/httpdocs/` per-domain. The
  recursive `find` used by pkgfence (`-maxdepth 6`) catches
  `package-lock.json`, `requirements.txt`, etc. in any vhost.
- Schedule scans outside Plesk's nightly maintenance windows — use
  read-only ACLs so even if a scan collides with a Plesk file-touch,
  nothing breaks.

## Cloudflare tunnel hosts (dev-host-2)

The Cloudflare tunnel only exposes HTTP(S). pkgfence reaches the LXC
directly via SSH on the private address (e.g. `192.0.2.11`). No tunnel
involvement. If the LXC is only reachable via Tailscale or a bastion,
use a host alias in `~/.ssh/config` and leave `key_file` unset.

## Exit codes

Same as local scan:

- `0` clean
- `1` findings at or above `--fail-on`
- `2` scanner error
- `3` configuration / registry error

SSH unreachable is NOT exit 2 — it emits a `SCAN_ERROR` finding (severity
`info`) and keeps scanning other targets, exactly mirroring local scan
behavior. The report clearly shows which targets failed.

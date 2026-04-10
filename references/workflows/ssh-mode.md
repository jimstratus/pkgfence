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
sudo setfacl -R -d -m u:scanuser:rX,mask::rwx /var/www  # default ACL for new files
```

**WARNING — the `mask::rwx` in the default ACL is load-bearing.**
Without it, adding a default user entry recomputes the directory's
default mask to `r-x`, which caps the effective permissions of the
owning group on any file subsequently created in that directory. On
Plesk hosts this silently strips write from the `psaserv` group on
PHP-FPM sockets, breaking every website on the host. The explicit
`mask::rwx` preserves the original group permissions. (Discovered
2026-04-10 on bespin — 100 sockets broken; mars was a time bomb.)

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

## Publish (centralized report sink)

When an operator runs scans from multiple hosts (SCANHOST, hl-cb2, a
future watch-mode-on-host agent on mars, etc.), reviewing reports means
SSH-ing to each scanner machine and reading local files. The publish
sink solves this by pushing all three artifacts (markdown report, SARIF,
audit JSONL) to a single central host after every scan. Operators can
review findings from any scanner in one place without touching each
machine individually. This also lays the groundwork for a Phase 4
watch-mode-on-host use case where a daemon runs on each remote and the
central sink aggregates results in near-real-time.

### YAML frontmatter

Every report now opens with a `---`-delimited YAML block that embeds
scan metadata before the human-readable content begins. This lets
downstream tooling (dashboards, grep, simple scripts) extract structured
data without parsing the markdown prose.

Example frontmatter from a live scan:

```yaml
---
run_id: 20260408T042855Z-89cc08ce
timestamp: '2026-04-08T04:29:12.027490+00:00'
scanner_host: SCANHOST
pkgfence_version: 0.2.0
scanner_version: 2.3.3
exit_code: 0
targets_scanned: 4
findings_total: 69
findings_by_severity:
  critical: 0
  high: 0
  medium: 24
  low: 45
  info: 0
  other: 0
degraded_modes: []
ssh_targets:
- dev-host-1
- dev-host-2
local_roots:
- D:/projects/pkgfence
---
```

### Configuring a sink

Add a `publish` key to your registry YAML:

```yaml
publish:
  - type: scp
    destination: pkgfence@control.example
    key_file: ~/.ssh/pkgfence-publish
    remote_base: /opt/pkgfence-reports
    include: [md, sarif, jsonl]
```

Field reference:

- `type` — transport type. Only `scp` is supported in v0.2.0.
- `destination` — `<user>@<host>` SSH destination for the sink.
- `key_file` — path to a dedicated private key. Optional; if omitted,
  falls back to `~/.ssh/config` defaults (agent, identity files, etc.).
  Using a dedicated key is strongly recommended for automated publishing.
- `remote_base` — base directory on the receiving host. Defaults to
  `/opt/pkgfence-reports`. Each scanner's artifacts land in a
  subdirectory named after `socket.gethostname()` (e.g.,
  `/opt/pkgfence-reports/SCANHOST/`).
- `include` — list of artifact types to push. Accepted values: `md`
  (markdown report), `sarif`, `jsonl` (audit log). Defaults to all
  three.

### One-time setup on the receiving host

```bash
# As an admin user with sudo on the sink host:
sudo useradd -r -m -s /bin/bash -c "pkgfence report sink" pkgfence
sudo mkdir -p /opt/pkgfence-reports
sudo chown -R pkgfence:pkgfence /opt/pkgfence-reports
sudo chmod 750 /opt/pkgfence-reports
sudo -u pkgfence mkdir -p /home/pkgfence/.ssh
sudo -u pkgfence touch /home/pkgfence/.ssh/authorized_keys
sudo chmod 700 /home/pkgfence/.ssh
sudo chmod 600 /home/pkgfence/.ssh/authorized_keys
```

```bash
# On the SCANNER host: generate a dedicated keypair and install the pubkey:
ssh-keygen -t ed25519 -f ~/.ssh/pkgfence-publish -N "" -C "pkgfence publish from $(hostname)"
cat ~/.ssh/pkgfence-publish.pub | ssh <admin>@<sink-host> 'sudo tee -a /home/pkgfence/.ssh/authorized_keys'
```

### Verification

Test the connection manually before relying on pkgfence to push:

```bash
echo "probe $(date)" > /tmp/probe.txt
scp -i ~/.ssh/pkgfence-publish -o IdentitiesOnly=yes -o BatchMode=yes \
    /tmp/probe.txt pkgfence@<sink-host>:/opt/pkgfence-reports/
ssh -i ~/.ssh/pkgfence-publish -o IdentitiesOnly=yes -o BatchMode=yes \
    pkgfence@<sink-host> 'cat /opt/pkgfence-reports/probe.txt && rm /opt/pkgfence-reports/probe.txt'
rm /tmp/probe.txt
```

**Why `IdentitiesOnly=yes` is required.** Without it, ssh fans out every
key loaded in ssh-agent before reaching the key specified by `-i`. On
hosts with a strict `MaxAuthTries` limit (the OpenSSH default is 6), the
agent's keys exhaust the budget before the publish key is tried, and the
server closes the connection with "Too many authentication failures".
`BatchMode=yes` ensures no password prompt blocks an unattended scan.
Both options are baked into pkgfence's automated scp invocations, and
both are reproduced in the manual probe above so you can verify the
exact behavior pkgfence will use.

### Failure semantics

Publish is best-effort. If scp fails (network error, key mismatch,
disk full on the sink), the error is logged to stderr but does **not**
change the scan exit code and does **not** modify the local report. The
local report remains the authoritative source of truth — a failed
publish never invalidates a successful scan. Future enhancement: persist
publish failures to a state file so the next scan's `degraded_modes`
field surfaces the previous failure without requiring the operator to
inspect stderr.

### Multi-scanner architecture preview

Each scanner host gets its own subdirectory under `remote_base` because
pkgfence auto-prepends `socket.gethostname()` before pushing. When more
scanners come online (e.g., Phase 4 watch-mode-on-host on mars or
bespin), their artifacts land in sibling subdirectories automatically —
no sink-side configuration required.

```
/opt/pkgfence-reports/
├── SCANHOST/                # this scanner
├── hl-cb2/                 # future
└── mars/                   # future (when watch-mode-on-host lands)
```

## Exit codes

Same as local scan:

- `0` clean
- `1` findings at or above `--fail-on`
- `2` scanner error
- `3` configuration / registry error

SSH unreachable is NOT exit 2 — it emits a `SCAN_ERROR` finding (severity
`info`) and keeps scanning other targets, exactly mirroring local scan
behavior. The report clearly shows which targets failed.

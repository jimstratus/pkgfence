"""Remote L1 discovery — uses SSHRunner to walk discover_paths on a remote
host and yield RemoteManifest records.

Uses only S3-allowlisted commands:
    find <discover_paths> -maxdepth N -type f ( -name 'package-lock.json' -o ... )

Grouping parens are passed BARE — SSHRunner shlex-quotes every argument
centrally before the remote shell sees it (issue #7).
    sha256sum <path>

Never retrieves manifest contents. Never writes anything. Path + hash only.
"""
import re
from typing import Iterator

from scripts.discover import MANIFEST_ECOSYSTEM, DEFAULT_EXCLUDES
from scripts.lib.remote_types import RemoteManifest
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError
from scripts.lib.logger import get_logger

log = get_logger(__name__)

# Max depth for remote find — keep reasonable for vhost-style layouts
REMOTE_MAX_DEPTH = 6


def _build_find_command(discover_paths: list[str]) -> list[str]:
    """Build a `find` argv that matches all known manifest filenames,
    pruning directories in DEFAULT_EXCLUDES (node_modules, .git, etc.)."""
    cmd = ["find"] + list(discover_paths)
    cmd += ["-maxdepth", str(REMOTE_MAX_DEPTH)]

    # Prune group: skip DEFAULT_EXCLUDES directories.
    # Sort for deterministic argv (DEFAULT_EXCLUDES is a frozenset).
    cmd += ["("]
    first = True
    for exc in sorted(DEFAULT_EXCLUDES):
        if not first:
            cmd += ["-o"]
        cmd += ["-name", exc]
        first = False
    cmd += [")", "-prune", "-o"]

    # Match group: files with manifest filenames, with explicit -print
    # so pruned directories are not printed by the default action.
    cmd += ["-type", "f", "("]
    first = True
    for name in MANIFEST_ECOSYSTEM:
        if not first:
            cmd += ["-o"]
        cmd += ["-name", name]
        first = False
    cmd += [")", "-print"]
    return cmd


def discover_remote_manifests(
    target: dict,
    runner: SSHRunner,
) -> Iterator[RemoteManifest]:
    """Walk a remote host's discover_paths via SSH `find` + `sha256sum`.

    Args:
        target: ssh registry entry (must have name, host, tier; optionally discover_paths)
        runner: an SSHRunner bound to this host

    Yields:
        RemoteManifest records, one per discovered lockfile.

    Raises:
        SSHUnreachableError: if the remote host becomes unreachable during
            the find call OR mid-iteration during sha256sum calls. Because
            this is a generator, some records may have already been yielded
            when the exception raises. Callers should wrap the full
            list(...) call to handle partial results correctly — see
            discover_remote_safely() in Task 7 for the canonical pattern.
    """
    discover_paths = target.get("discover_paths") or []
    if not discover_paths:
        log.info("ssh target %s has no discover_paths; skipping", target.get("name"))
        return

    try:
        find_output = runner.run(_build_find_command(discover_paths))
    except SSHUnreachableError:
        # S1 preserved — re-raise. scan_command wraps with SCAN_ERROR handling.
        raise

    paths = [line.strip() for line in find_output.splitlines() if line.strip()]
    log.info("ssh target %s: find returned %d manifest candidates",
             target.get("name"), len(paths))

    for path in paths:
        filename = path.rsplit("/", 1)[-1]
        ecosystem = MANIFEST_ECOSYSTEM.get(filename)
        if ecosystem is None:
            continue  # shouldn't happen given the find filter, but be defensive

        # Hash this manifest via sha256sum
        try:
            hash_output = runner.run(["sha256sum", path])
        except SSHUnreachableError:
            raise
        # sha256sum output: "<hash>  <path>\n"
        hash_hex = hash_output.strip().split(None, 1)[0] if hash_output.strip() else ""

        # Defensive: sha256 must be 64 hex chars. A non-matching value means
        # sha256sum output was in an unexpected format (e.g. BSD-style
        # "SHA256 (path) = hash"). Log and skip rather than storing garbage.
        if not re.fullmatch(r"[0-9a-f]{64}", hash_hex):
            log.warning("ssh target %s: sha256sum for %s returned unexpected format; skipping",
                        target.get("name"), path)
            continue

        yield {
            "target": target["name"],
            "host": target["host"],
            "path": path,
            "ecosystem": ecosystem,
            "manifest_hash": hash_hex,
            "tier": target.get("tier", 1),
        }


def discover_remote_safely(
    target: dict,
    runner: SSHRunner,
) -> Iterator[RemoteManifest]:
    """Wrapper around discover_remote_manifests that converts an unreachable
    ssh target into a single SCAN_ERROR record instead of propagating the
    exception. This matches scan_manifest_safely's pattern for local scans:
    one bad target must not block the entire scan.

    S1 is NOT violated here — we don't fall back to a local scan. We emit a
    diagnostic record and move on. The report clearly shows the target failed.
    """
    try:
        yield from discover_remote_manifests(target, runner)
    except SSHUnreachableError as e:
        yield {
            "target": target["name"],
            "host": target.get("host", ""),
            "path": "",
            "ecosystem": "SCAN_ERROR",
            "manifest_hash": "",
            "tier": target.get("tier", 1),
            "error": str(e),
        }

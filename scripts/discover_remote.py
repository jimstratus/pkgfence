"""Remote L1 discovery — uses SSHRunner to walk discover_paths on a remote
host and yield RemoteManifest records.

Uses only S3-allowlisted commands:
    find <discover_paths> -maxdepth N -type f \\( -name 'package-lock.json' -o ... \\)
    sha256sum <path>

Never retrieves manifest contents. Never writes anything. Path + hash only.
"""
from typing import Iterator

from scripts.discover import MANIFEST_ECOSYSTEM
from scripts.lib.remote_types import RemoteManifest
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError
from scripts.lib.logger import get_logger

log = get_logger(__name__)

# Max depth for remote find — keep reasonable for vhost-style layouts
REMOTE_MAX_DEPTH = 6


def _build_find_command(discover_paths: list[str]) -> list[str]:
    """Build a `find` argv that matches all known manifest filenames."""
    cmd = ["find"] + list(discover_paths)
    cmd += ["-maxdepth", str(REMOTE_MAX_DEPTH), "-type", "f", "("]
    first = True
    for name in MANIFEST_ECOSYSTEM:
        if not first:
            cmd += ["-o"]
        cmd += ["-name", name]
        first = False
    cmd += [")"]
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

    for line in find_output.splitlines():
        path = line.strip()
        if not path:
            continue
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

        yield {
            "target": target["name"],
            "host": target["host"],
            "path": path,
            "ecosystem": ecosystem,
            "manifest_hash": hash_hex,
            "tier": target.get("tier", 1),
        }

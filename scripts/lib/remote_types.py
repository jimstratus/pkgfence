"""TypedDicts for remote (SSH) manifest discovery — Phase 2."""
from typing import TypedDict


class RemoteManifest(TypedDict):
    target: str         # ssh target name (e.g. "dev-host-1")
    host: str           # host (for disambiguation in reports)
    path: str           # remote absolute path to the manifest
    ecosystem: str      # npm | python | rust | go | ruby | php | java
    manifest_hash: str  # sha256sum from remote
    tier: int

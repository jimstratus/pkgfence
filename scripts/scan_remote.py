"""Remote L2 scanning — runs osv-scanner on remote hosts via SSH.

Pattern B: the scanner runs on the remote. We never copy code locally;
we only receive osv-scanner's JSON output over SSH stdout. This is the
S4 load-bearing promise (see SAFETY_INVARIANTS.md).
"""
import json

from scripts.lib.remote_types import RemoteManifest
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError
from scripts.lib.types import Finding, new_finding
from scripts.scan_local import parse_osv_output, ScannerError, _findings_from_result
from scripts.lib.logger import get_logger

log = get_logger(__name__)


def _scan_error_finding(manifest: RemoteManifest, description: str) -> Finding:
    """Build a SCAN_ERROR Finding from a manifest and a diagnostic message.
    Shared by all three SCAN_ERROR branches in scan_remote_manifest."""
    target = manifest.get("target", "unknown")
    return new_finding(
        purl=f"pkg:scan-error/{target}@-",
        vuln_id="SCAN_ERROR",
        severity="info",
        manifest_path=manifest.get("path", ""),
        target=target,
        status="SCAN_ERROR",
        description=description,
    )


def scan_remote_manifest(
    manifest: RemoteManifest,
    runner: SSHRunner,
    scanner_path: str | None = None,
) -> list[Finding]:
    """Run osv-scanner on the remote host against a single remote manifest.

    Args:
        manifest: a RemoteManifest dict (from discover_remote)
        runner: SSHRunner bound to the remote host
        scanner_path: absolute path to osv-scanner on the remote; falls back
            to bare 'osv-scanner' if None (relies on remote PATH)

    Returns:
        list[Finding] (possibly one SCAN_ERROR record on failure).
    """
    # Pass-through: manifests already marked SCAN_ERROR at discovery time
    if manifest.get("ecosystem") == "SCAN_ERROR":
        return [_scan_error_finding(
            manifest,
            manifest.get("error", "remote discovery failed"),
        )]

    cmd = [scanner_path or "osv-scanner", "-L", manifest["path"], "--format", "json"]
    try:
        raw = runner.run(cmd)
    except SSHUnreachableError as e:
        log.warning("remote scan %s unreachable: %s", manifest.get("target"), e)
        return [_scan_error_finding(manifest, f"ssh unreachable: {e}")]

    try:
        return parse_osv_output(
            raw,
            manifest_path=manifest["path"],
            target=manifest["target"],
        )
    except ScannerError as e:
        return [_scan_error_finding(manifest, f"osv-scanner output parse failed: {e}")]


def _parse_batch_output(raw: str, manifests: list[RemoteManifest]) -> list[Finding]:
    """Map each batch result back to its manifest via source.path."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ScannerError(f"osv-scanner batch returned invalid JSON: {e}") from e
    by_path = {m["path"]: m for m in manifests}
    findings: list[Finding] = []
    for result in data.get("results", []):
        src = (result.get("source") or {}).get("path", "")
        manifest = by_path.get(src)
        if manifest is None:
            log.warning("batch scan returned unknown source path %r; skipping", src)
            continue
        findings.extend(_findings_from_result(
            result, manifest_path=manifest["path"], target=manifest["target"]))
    return findings


def scan_remote_manifests(
    manifests: list[RemoteManifest],
    runner: SSHRunner,
    scanner_path: str | None = None,
) -> list[Finding]:
    """Scan a target's manifests with ONE osv-scanner invocation (repeated
    -L flags — issue #19.3: per-manifest calls cost N cold starts). Falls
    back to per-manifest scanning when the batch output is unusable, which
    preserves per-manifest SCAN_ERROR isolation."""
    findings: list[Finding] = []
    scannable: list[RemoteManifest] = []
    for m in manifests:
        if m.get("ecosystem") == "SCAN_ERROR":
            findings.append(_scan_error_finding(
                m, m.get("error", "remote discovery failed")))
        else:
            scannable.append(m)
    if not scannable:
        return findings

    cmd = [scanner_path or "osv-scanner"]
    for m in scannable:
        cmd += ["-L", m["path"]]
    cmd += ["--format", "json"]
    try:
        raw = runner.run(cmd)
        return findings + _parse_batch_output(raw, scannable)
    except SSHUnreachableError as e:
        log.warning("remote scan %s unreachable: %s", scannable[0].get("target"), e)
        return findings + [
            _scan_error_finding(m, f"ssh unreachable: {e}") for m in scannable
        ]
    except ScannerError as e:
        log.warning("batch scan unusable (%s); retrying per-manifest", e)
        for m in scannable:
            findings.extend(scan_remote_manifest(m, runner, scanner_path=scanner_path))
        return findings

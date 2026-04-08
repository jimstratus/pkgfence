"""Remote L2 scanning — runs osv-scanner on remote hosts via SSH.

Pattern B: the scanner runs on the remote. We never copy code locally;
we only receive osv-scanner's JSON output over SSH stdout. This is the
S4 load-bearing promise (see SAFETY_INVARIANTS.md).
"""
from scripts.lib.remote_types import RemoteManifest
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError
from scripts.lib.types import Finding, new_finding
from scripts.scan_local import parse_osv_output, ScannerError
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
) -> list[Finding]:
    """Run osv-scanner on the remote host against a single remote manifest.

    Args:
        manifest: a RemoteManifest dict (from discover_remote)
        runner: SSHRunner bound to the remote host

    Returns:
        list[Finding] (possibly one SCAN_ERROR record on failure).
    """
    # Pass-through: manifests already marked SCAN_ERROR at discovery time
    if manifest.get("ecosystem") == "SCAN_ERROR":
        return [_scan_error_finding(
            manifest,
            manifest.get("error", "remote discovery failed"),
        )]

    cmd = ["osv-scanner", "-L", manifest["path"], "--format", "json"]
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


def scan_remote_manifests(
    manifests: list[RemoteManifest],
    runner: SSHRunner,
) -> list[Finding]:
    """Scan a batch of remote manifests using a single SSHRunner.
    Per-manifest errors are isolated via scan_remote_manifest's SCAN_ERROR wrapping.
    """
    findings: list[Finding] = []
    for m in manifests:
        findings.extend(scan_remote_manifest(m, runner))
    return findings

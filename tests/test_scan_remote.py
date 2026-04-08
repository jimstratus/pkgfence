"""Tests for remote L2 scanning (Phase 2 SSH mode)."""
from unittest.mock import MagicMock, patch

from scripts.lib.remote_types import RemoteManifest
from scripts.lib.ssh_runner import SSHUnreachableError
from scripts.scan_local import ScannerError
from scripts.scan_remote import scan_remote_manifest, scan_remote_manifests


OSV_JSON_FIXTURE = """
{
  "results": [
    {
      "source": {"path": "/var/www/app/package-lock.json", "type": "lockfile"},
      "packages": [
        {
          "package": {"name": "lodash", "version": "4.17.10", "ecosystem": "npm"},
          "vulnerabilities": [
            {"id": "GHSA-jf85-cpcp-j695", "summary": "Prototype Pollution",
             "severity": [{"type": "CVSS_V3", "score": "7.4"}],
             "aliases": ["CVE-2019-10744"]}
          ]
        }
      ]
    }
  ]
}
"""


def test_scan_remote_manifest_runs_osv_scanner_remotely():
    """Remote scan invokes `osv-scanner -L <path> --format json` via SSHRunner."""
    runner = MagicMock()
    runner.host = "dev-host-1.example"
    runner.run.return_value = OSV_JSON_FIXTURE
    manifest = {
        "target": "dev-host-1",
        "host": "dev-host-1.example",
        "path": "/var/www/app/package-lock.json",
        "ecosystem": "npm",
        "manifest_hash": "a" * 64,
        "tier": 2,
    }
    findings = scan_remote_manifest(manifest, runner)
    args = runner.run.call_args[0][0]
    assert args[0] == "osv-scanner"
    assert "-L" in args
    assert args[args.index("-L") + 1] == "/var/www/app/package-lock.json"
    assert "--format" in args
    assert args[args.index("--format") + 1] == "json"
    # Verify parse result
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "GHSA-jf85-cpcp-j695"
    assert findings[0]["target"] == "dev-host-1"


def test_scan_remote_manifest_skips_scan_error_manifests():
    """Manifests with ecosystem=SCAN_ERROR are already failed; don't re-scan."""
    runner = MagicMock()
    manifest = {
        "target": "dev-host-1",
        "host": "h",
        "path": "",
        "ecosystem": "SCAN_ERROR",
        "manifest_hash": "",
        "tier": 2,
        "error": "unreachable",
    }
    findings = scan_remote_manifest(manifest, runner)
    runner.run.assert_not_called()
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "SCAN_ERROR"
    assert findings[0]["target"] == "dev-host-1"


def test_scan_remote_manifest_ssh_unreachable_becomes_scan_error():
    """SSHUnreachableError during the osv-scanner call produces a SCAN_ERROR
    Finding with 'ssh unreachable' in the description (distinguishable from
    the pass-through and parse-failure SCAN_ERROR branches)."""
    runner = MagicMock()
    runner.run.side_effect = SSHUnreachableError("connection timeout")
    manifest: RemoteManifest = {
        "target": "dev-host-1",
        "host": "dev-host-1.example",
        "path": "/var/www/app/package-lock.json",
        "ecosystem": "npm",
        "manifest_hash": "a" * 64,
        "tier": 2,
    }
    findings = scan_remote_manifest(manifest, runner)
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "SCAN_ERROR"
    assert findings[0]["target"] == "dev-host-1"
    assert "ssh unreachable" in findings[0]["description"]
    assert "connection timeout" in findings[0]["description"]


def test_scan_remote_manifest_parse_failure_becomes_scan_error():
    """ScannerError from parse_osv_output produces a SCAN_ERROR Finding
    with 'output parse failed' in the description."""
    runner = MagicMock()
    runner.run.return_value = "{not valid json"
    manifest: RemoteManifest = {
        "target": "dev-host-1",
        "host": "dev-host-1.example",
        "path": "/var/www/app/package-lock.json",
        "ecosystem": "npm",
        "manifest_hash": "a" * 64,
        "tier": 2,
    }
    with patch("scripts.scan_remote.parse_osv_output",
               side_effect=ScannerError("invalid json")):
        findings = scan_remote_manifest(manifest, runner)
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "SCAN_ERROR"
    assert "output parse failed" in findings[0]["description"]
    assert "invalid json" in findings[0]["description"]


def test_scan_remote_manifests_batch_preserves_order_and_isolates_errors():
    """scan_remote_manifests concatenates findings from multiple manifests in
    order. A SCAN_ERROR on one manifest does NOT prevent later manifests
    from being scanned."""
    runner = MagicMock()
    runner.run.side_effect = [
        OSV_JSON_FIXTURE,
        OSV_JSON_FIXTURE,  # second good manifest
    ]

    manifests: list[RemoteManifest] = [
        {
            "target": "dev-host-1",
            "host": "dev-host-1.example",
            "path": "/var/www/app1/package-lock.json",
            "ecosystem": "npm",
            "manifest_hash": "a" * 64,
            "tier": 2,
        },
        {
            # Pre-marked SCAN_ERROR — never calls runner.run
            "target": "dev-host-1",
            "host": "dev-host-1.example",
            "path": "",
            "ecosystem": "SCAN_ERROR",
            "manifest_hash": "",
            "tier": 2,
            "error": "discovery failed",
        },
        {
            "target": "dev-host-1",
            "host": "dev-host-1.example",
            "path": "/var/www/app3/package-lock.json",
            "ecosystem": "npm",
            "manifest_hash": "c" * 64,
            "tier": 2,
        },
    ]
    findings = scan_remote_manifests(manifests, runner)
    # 1 real finding from manifest 1, 1 SCAN_ERROR from manifest 2, 1 real from manifest 3
    assert len(findings) == 3
    assert findings[0]["vuln_id"] == "GHSA-jf85-cpcp-j695"
    assert findings[1]["vuln_id"] == "SCAN_ERROR"
    assert "discovery failed" in findings[1]["description"]
    assert findings[2]["vuln_id"] == "GHSA-jf85-cpcp-j695"
    # Verify runner.run was called exactly twice (not for the SCAN_ERROR manifest)
    assert runner.run.call_count == 2

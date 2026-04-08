"""Tests for remote L2 scanning (Phase 2 SSH mode)."""
from unittest.mock import MagicMock

from scripts.scan_remote import scan_remote_manifest


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

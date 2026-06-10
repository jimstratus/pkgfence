"""Tests for remote L2 scanning (Phase 2 SSH mode)."""
from unittest.mock import MagicMock, patch

from scripts.lib.remote_types import RemoteManifest
from scripts.lib.ssh_runner import SSHUnreachableError
from scripts.scan_local import ScannerError
from scripts.scan_remote import scan_remote_manifest, scan_remote_manifests


def test_scan_remote_manifest_uses_scanner_path(mocker):
    """When scanner_path is provided, it replaces the bare 'osv-scanner' verb."""
    manifest = {
        "target": "test-host", "host": "10.0.0.1", "path": "/var/www/package-lock.json",
        "ecosystem": "npm", "manifest_hash": "abc123", "tier": 1,
    }
    mock_runner = mocker.MagicMock()
    mock_runner.run.return_value = '{"results": []}'
    scan_remote_manifest(manifest, mock_runner, scanner_path="/opt/bin/osv-scanner")
    cmd = mock_runner.run.call_args[0][0]
    assert cmd[0] == "/opt/bin/osv-scanner"


def test_scan_remote_manifest_default_scanner(mocker):
    """Without scanner_path, uses bare 'osv-scanner'."""
    manifest = {
        "target": "test-host", "host": "10.0.0.1", "path": "/var/www/package-lock.json",
        "ecosystem": "npm", "manifest_hash": "abc123", "tier": 1,
    }
    mock_runner = mocker.MagicMock()
    mock_runner.run.return_value = '{"results": []}'
    scan_remote_manifest(manifest, mock_runner)
    cmd = mock_runner.run.call_args[0][0]
    assert cmd[0] == "osv-scanner"


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


BATCH_OSV_JSON_FIXTURE = """
{
  "results": [
    {
      "source": {"path": "/var/www/app1/package-lock.json", "type": "lockfile"},
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
    },
    {
      "source": {"path": "/var/www/app3/package-lock.json", "type": "lockfile"},
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


def test_scan_remote_manifests_batch_preserves_order_and_isolates_errors():
    """scan_remote_manifests runs ONE batched osv-scanner call for all scannable
    manifests (#19.3) and maps results back via source.path. A pre-marked
    SCAN_ERROR manifest passes through as a SCAN_ERROR Finding and is excluded
    from the batch invocation."""
    runner = MagicMock()
    runner.run.return_value = BATCH_OSV_JSON_FIXTURE

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
            # Pre-marked SCAN_ERROR — excluded from batch, passes through
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
    # 1 SCAN_ERROR (passthrough) + 2 real findings from the batched scan
    assert len(findings) == 3
    vuln_ids = sorted(f["vuln_id"] for f in findings)
    assert vuln_ids == ["GHSA-jf85-cpcp-j695", "GHSA-jf85-cpcp-j695", "SCAN_ERROR"]
    scan_error = next(f for f in findings if f["vuln_id"] == "SCAN_ERROR")
    assert "discovery failed" in scan_error["description"]
    # Verify runner.run was called exactly ONCE (single batched invocation)
    assert runner.run.call_count == 1
    cmd = runner.run.call_args.args[0]
    assert cmd.count("-L") == 2


def test_batch_scan_single_invocation_with_repeated_L_flags():
    runner = MagicMock()
    runner.run.return_value = (
        '{"results": ['
        '{"source": {"path": "/a/package-lock.json"}, "packages": []},'
        '{"source": {"path": "/b/package-lock.json"}, "packages": []}'
        ']}'
    )
    manifests = [
        {"target": "bespin", "host": "h", "path": "/a/package-lock.json",
         "ecosystem": "npm", "manifest_hash": "", "tier": 1},
        {"target": "bespin", "host": "h", "path": "/b/package-lock.json",
         "ecosystem": "npm", "manifest_hash": "", "tier": 1},
    ]
    findings = scan_remote_manifests(manifests, runner)
    assert runner.run.call_count == 1
    cmd = runner.run.call_args.args[0]
    assert cmd.count("-L") == 2
    assert findings == []


def test_batch_scan_falls_back_to_per_manifest_on_parse_error():
    runner = MagicMock()
    good = '{"results": []}'
    runner.run.side_effect = ["NOT JSON", good, good]  # batch fails, 2 singles
    manifests = [
        {"target": "bespin", "host": "h", "path": "/a/package-lock.json",
         "ecosystem": "npm", "manifest_hash": "", "tier": 1},
        {"target": "bespin", "host": "h", "path": "/b/package-lock.json",
         "ecosystem": "npm", "manifest_hash": "", "tier": 1},
    ]
    findings = scan_remote_manifests(manifests, runner)
    assert runner.run.call_count == 3
    assert findings == []  # per-manifest path succeeded; no SCAN_ERROR

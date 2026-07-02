"""End-to-end scan_command tests with SSH targets (Phase 2)."""
import json
import pytest
from unittest.mock import patch, MagicMock

from scripts.scan_command import run_scan
from scripts.lib.ssh_runner import SSHUnreachableError


OSV_JSON = (
    '{"results":[{"source":{"path":"/var/www/app/package-lock.json","type":"lockfile"},'
    '"packages":[{"package":{"name":"lodash","version":"4.17.10","ecosystem":"npm"},'
    '"vulnerabilities":[{"id":"GHSA-jf85-cpcp-j695","summary":"Prototype Pollution",'
    '"severity":[{"type":"CVSS_V3","score":"7.4"}],"aliases":["CVE-2019-10744"]}]}]}]}'
)


def test_run_scan_with_ssh_target_includes_remote_findings(tmp_path, tmp_state):
    """A registry with one ssh target produces a report that includes the
    remote finding, tagged with the ssh target name."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: dev-host-1\n"
        "    host: 192.0.2.10\n"
        "    user: devuser\n"
        "    tier: 1\n"
        "    discover_paths: ['/var/www']\n"
        "github: []\n"
    )

    def fake_ssh_run(self, command):
        if command[0] == "find":
            return "/var/www/app/package-lock.json\n"
        if command[0] == "sha256sum":
            return "a" * 64 + "  /var/www/app/package-lock.json\n"
        if command[0] == "osv-scanner":
            return OSV_JSON
        raise AssertionError(f"unexpected command: {command}")

    def fake_ssh_run_with_rc(self, command):
        # ls -d for the batched is-installed check (issue #19.1): echo back
        # the queried install paths so every package reads as installed.
        if command[:2] == ["ls", "-d"]:
            paths = command[2:]
            return ("\n".join(paths) + "\n", 0)
        raise AssertionError(f"unexpected run_with_rc command: {command}")

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_ssh_run), \
         patch("scripts.lib.ssh_runner.SSHRunner.run_with_rc", new=fake_ssh_run_with_rc):
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
            mock_kev._known_set = set()
            mock_kev._loaded = True
            mock_kev.is_degraded = False
            mock_kev.is_known_exploited.return_value = False
            mock_kev.refresh = MagicMock()
            mock_kev_cls.return_value = mock_kev
            with patch("scripts.scan_command.EPSSClient") as mock_epss_cls:
                mock_epss = MagicMock()
                mock_epss.is_degraded = False
                mock_epss.feed_timestamp = None
                mock_epss.refresh = MagicMock()
                mock_epss.lookup.return_value = None
                mock_epss_cls.return_value = mock_epss
                with patch("scripts.scan_command.GHSAHTTPClient") as mock_ghsa_cls:
                    mock_ghsa = MagicMock()
                    mock_ghsa.is_degraded = False
                    mock_ghsa.is_stale = False
                    mock_ghsa.advisories_fetched = 0
                    mock_ghsa.advisories_cached = 0
                    mock_ghsa.fetch.return_value = None
                    mock_ghsa_cls.return_value = mock_ghsa

                    exit_code, report_path = run_scan(
                        registry_path=reg,
                        state_dir=tmp_state,
                        fail_on="high",
                    )

    assert exit_code == 1
    report_text = report_path.read_text(encoding="utf-8")
    assert "GHSA-jf85-cpcp-j695" in report_text
    assert "dev-host-1" in report_text

    # BUG 15-F regression: audit log must count remote manifests too.
    audit_dir = tmp_state / "audit.jsonl.d"
    audit_files = list(audit_dir.glob("*.jsonl"))
    assert len(audit_files) == 1, f"expected one audit file, got {audit_files}"
    audit_record = json.loads(audit_files[0].read_text(encoding="utf-8").strip())
    assert audit_record["manifests_scanned"] >= 1, (
        f"audit manifests_scanned should count remote manifests, got "
        f"{audit_record['manifests_scanned']}"
    )


def test_run_scan_with_unreachable_ssh_target_exit_1_not_2(tmp_path, tmp_state):
    """SSH unreachable must not crash the scan — it should emit a SCAN_ERROR
    record and exit 0 (when fail_on is strict enough that info-severity
    SCAN_ERROR records don't trip the threshold)."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: mars\n"
        "    host: unreachable.invalid\n"
        "    user: scanuser\n"
        "    tier: 1\n"
        "    discover_paths: ['/var/www']\n"
        "github: []\n"
    )

    def fake_run(self, command):
        raise SSHUnreachableError("host unreachable")

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_run):
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
            mock_kev._known_set = set()
            mock_kev._loaded = True
            mock_kev.is_degraded = False
            mock_kev.refresh = MagicMock()
            mock_kev_cls.return_value = mock_kev
            with patch("scripts.scan_command.EPSSClient") as mock_epss_cls:
                mock_epss = MagicMock()
                mock_epss.is_degraded = False
                mock_epss.feed_timestamp = None
                mock_epss.refresh = MagicMock()
                mock_epss.lookup.return_value = None
                mock_epss_cls.return_value = mock_epss
                with patch("scripts.scan_command.GHSAHTTPClient") as mock_ghsa_cls:
                    mock_ghsa = MagicMock()
                    mock_ghsa.is_degraded = False
                    mock_ghsa.is_stale = False
                    mock_ghsa.advisories_fetched = 0
                    mock_ghsa.advisories_cached = 0
                    mock_ghsa.fetch.return_value = None
                    mock_ghsa_cls.return_value = mock_ghsa
                    exit_code, report_path = run_scan(
                        registry_path=reg,
                        state_dir=tmp_state,
                        fail_on="critical",
                    )

    # SCAN_ERROR findings have severity=info, so they don't trip fail-on=critical
    assert exit_code == 0
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "SCAN_ERROR" in report_text
    assert "mars" in report_text


def test_run_scan_with_two_ssh_targets_aggregates_findings(tmp_path, tmp_state):
    """With two ssh targets in the registry, findings from both targets are
    aggregated into the final report. Verifies the target_manifests filter
    (m['target'] == target['name']) correctly isolates per-target findings.

    Note: each host returns a *different* package version so dedup (keyed on
    purl+vuln_id) preserves both findings — host-a gets lodash@4.17.10 and
    host-b gets lodash@4.17.11, each paired with the same GHSA ID.
    """
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: host-a\n"
        "    host: host-a.example\n"
        "    user: u\n"
        "    tier: 1\n"
        "    discover_paths: ['/var/www']\n"
        "  - name: host-b\n"
        "    host: host-b.example\n"
        "    user: u\n"
        "    tier: 1\n"
        "    discover_paths: ['/opt']\n"
        "github: []\n"
    )

    # Per-host OSV payloads with distinct package versions so dedup keeps both.
    OSV_HOST_A = (
        '{"results":[{"source":{"path":"/host-a.example-app/package-lock.json","type":"lockfile"},'
        '"packages":[{"package":{"name":"lodash","version":"4.17.10","ecosystem":"npm"},'
        '"vulnerabilities":[{"id":"GHSA-jf85-cpcp-j695","summary":"Prototype Pollution",'
        '"severity":[{"type":"CVSS_V3","score":"7.4"}],"aliases":["CVE-2019-10744"]}]}]}]}'
    )
    OSV_HOST_B = (
        '{"results":[{"source":{"path":"/host-b.example-app/package-lock.json","type":"lockfile"},'
        '"packages":[{"package":{"name":"lodash","version":"4.17.11","ecosystem":"npm"},'
        '"vulnerabilities":[{"id":"GHSA-jf85-cpcp-j695","summary":"Prototype Pollution",'
        '"severity":[{"type":"CVSS_V3","score":"7.4"}],"aliases":["CVE-2019-10744"]}]}]}]}'
    )

    def fake_ssh_run(self, command):
        if command[0] == "find":
            # Path includes the host so each target gets a distinct manifest path.
            return f"/{self.host}-app/package-lock.json\n"
        if command[0] == "sha256sum":
            return "a" * 64 + f"  /{self.host}-app/package-lock.json\n"
        if command[0] == "osv-scanner":
            return OSV_HOST_A if self.host == "host-a.example" else OSV_HOST_B
        raise AssertionError(f"unexpected command: {command}")

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_ssh_run):
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
            mock_kev._known_set = set()
            mock_kev._loaded = True
            mock_kev.is_degraded = False
            mock_kev.is_known_exploited.return_value = False
            mock_kev.refresh = MagicMock()
            mock_kev_cls.return_value = mock_kev
            with patch("scripts.scan_command.EPSSClient") as mock_epss_cls:
                mock_epss = MagicMock()
                mock_epss.is_degraded = False
                mock_epss.feed_timestamp = None
                mock_epss.refresh = MagicMock()
                mock_epss.lookup.return_value = None
                mock_epss_cls.return_value = mock_epss

                exit_code, report_path = run_scan(
                    registry_path=reg,
                    state_dir=tmp_state,
                    fail_on="high",
                )

    assert exit_code == 1
    report_text = report_path.read_text(encoding="utf-8")
    # Both targets should contribute findings
    assert "host-a" in report_text
    assert "host-b" in report_text
    # The GHSA finding should appear
    assert "GHSA-jf85-cpcp-j695" in report_text


def test_run_scan_skips_tier2_ssh_targets_by_default(tmp_path, tmp_state):
    """SSH targets with tier != 1 are silently skipped by the default tier
    filter (matches how local roots are filtered)."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: tier2-host\n"
        "    host: tier2.example\n"
        "    user: u\n"
        "    tier: 2\n"  # Not in default tier_set={1}
        "    discover_paths: ['/var/www']\n"
        "github: []\n"
    )

    # fake_ssh_run raises on any call — if the target is filtered, we never get here
    def fake_ssh_run(self, command):
        raise AssertionError(f"tier-2 target should not be scanned; got {command}")

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_ssh_run):
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
            mock_kev._known_set = set()
            mock_kev._loaded = True
            mock_kev.is_degraded = False
            mock_kev.refresh = MagicMock()
            mock_kev_cls.return_value = mock_kev
            with patch("scripts.scan_command.EPSSClient") as mock_epss_cls:
                mock_epss = MagicMock()
                mock_epss.is_degraded = False
                mock_epss.feed_timestamp = None
                mock_epss.refresh = MagicMock()
                mock_epss.lookup.return_value = None
                mock_epss_cls.return_value = mock_epss
                with patch("scripts.scan_command.GHSAHTTPClient") as mock_ghsa_cls:
                    mock_ghsa = MagicMock()
                    mock_ghsa.is_degraded = False
                    mock_ghsa.is_stale = False
                    mock_ghsa.advisories_fetched = 0
                    mock_ghsa.advisories_cached = 0
                    mock_ghsa.fetch.return_value = None
                    mock_ghsa_cls.return_value = mock_ghsa

                    exit_code, report_path = run_scan(
                        registry_path=reg,
                        state_dir=tmp_state,
                        fail_on="critical",
                    )

    assert exit_code == 0
    report_text = report_path.read_text(encoding="utf-8")
    assert "GHSA-" not in report_text
    assert "SCAN_ERROR" not in report_text


def test_run_scan_with_adhoc_path_skips_ssh_targets(tmp_path, tmp_state):
    """adhoc_path builds a synthetic registry with ssh: [], so SSH targets
    in the on-disk registry are bypassed entirely when --path is used."""
    # Create a real registry with an ssh target that would fail if scanned
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: would-fail\n"
        "    host: would-fail.example\n"
        "    user: u\n"
        "    tier: 1\n"
        "    discover_paths: ['/var/www']\n"
        "github: []\n"
    )
    # Create an adhoc path with no manifests
    adhoc = tmp_path / "adhoc"
    adhoc.mkdir()

    def fake_ssh_run(self, command):
        raise AssertionError(f"adhoc mode should bypass SSH; got {command}")

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_ssh_run):
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
            mock_kev._known_set = set()
            mock_kev._loaded = True
            mock_kev.is_degraded = False
            mock_kev.refresh = MagicMock()
            mock_kev_cls.return_value = mock_kev
            with patch("scripts.scan_command.EPSSClient") as mock_epss_cls:
                mock_epss = MagicMock()
                mock_epss.is_degraded = False
                mock_epss.feed_timestamp = None
                mock_epss.refresh = MagicMock()
                mock_epss.lookup.return_value = None
                mock_epss_cls.return_value = mock_epss

                exit_code, report_path = run_scan(
                    registry_path=reg,
                    state_dir=tmp_state,
                    adhoc_path=adhoc,
                    fail_on="critical",
                )

    assert exit_code == 0


def test_run_scan_invokes_publish_when_sinks_configured(tmp_path, tmp_state):
    """When the registry has a publish: section, scan_command calls
    publish_run after writing the local artifacts. Mock publish_run to
    verify the call without actually invoking scp."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh: []\n"
        "github: []\n"
        "publish:\n"
        "  - type: scp\n"
        "    destination: pkgfence@control.example\n"
        "    key_file: ~/.ssh/pkgfence-publish\n"
    )

    with patch("scripts.scan_command.publish_run") as mock_publish:
        mock_publish.return_value = []
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
            mock_kev._known_set = set()
            mock_kev._loaded = True
            mock_kev.is_degraded = False
            mock_kev.is_known_exploited.return_value = False
            mock_kev.refresh = MagicMock()
            mock_kev_cls.return_value = mock_kev
            with patch("scripts.scan_command.EPSSClient") as mock_epss_cls:
                mock_epss = MagicMock()
                mock_epss.is_degraded = False
                mock_epss.feed_timestamp = None
                mock_epss.refresh = MagicMock()
                mock_epss.lookup.return_value = None
                mock_epss_cls.return_value = mock_epss

                exit_code, report_path = run_scan(
                    registry_path=reg,
                    state_dir=tmp_state,
                    fail_on="critical",
                )

    assert exit_code == 0
    # publish_run was called once with the configured sinks
    assert mock_publish.call_count == 1
    call_kwargs = mock_publish.call_args.kwargs
    assert len(call_kwargs["sinks"]) == 1
    assert call_kwargs["sinks"][0]["type"] == "scp"
    assert call_kwargs["sinks"][0]["destination"] == "pkgfence@control.example"
    # state_dir and run_id were also passed
    assert call_kwargs["state_dir"] == tmp_state
    assert "run_id" in call_kwargs


def test_run_scan_publish_failures_do_not_change_exit_code(tmp_path, tmp_state):
    """Even if publish_run reports failures, scan exit code is unchanged
    (publish is best-effort, scan verdict is the source of truth)."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh: []\n"
        "github: []\n"
        "publish:\n"
        "  - type: scp\n"
        "    destination: pkgfence@control.example\n"
    )

    with patch("scripts.scan_command.publish_run") as mock_publish:
        mock_publish.return_value = ["publish: FAIL pkgfence@control.example: simulated"]
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
            mock_kev._known_set = set()
            mock_kev._loaded = True
            mock_kev.is_degraded = False
            mock_kev.refresh = MagicMock()
            mock_kev_cls.return_value = mock_kev
            with patch("scripts.scan_command.EPSSClient") as mock_epss_cls:
                mock_epss = MagicMock()
                mock_epss.is_degraded = False
                mock_epss.feed_timestamp = None
                mock_epss.refresh = MagicMock()
                mock_epss.lookup.return_value = None
                mock_epss_cls.return_value = mock_epss

                exit_code, _ = run_scan(
                    registry_path=reg,
                    state_dir=tmp_state,
                    fail_on="critical",
                )

    # Even with publish failures, exit code stays 0 (clean local scan)
    assert exit_code == 0

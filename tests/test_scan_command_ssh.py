"""End-to-end scan_command tests with SSH targets (Phase 2)."""
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

    with patch("scripts.lib.ssh_runner.SSHRunner.run", new=fake_ssh_run):
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
            mock_kev._known_set = set()
            mock_kev._loaded = True
            mock_kev.is_degraded = False
            mock_kev.is_known_exploited.return_value = False
            mock_kev.refresh = MagicMock()
            mock_kev_cls.return_value = mock_kev

            exit_code, report_path = run_scan(
                registry_path=reg,
                state_dir=tmp_state,
                fail_on="high",
            )

    assert exit_code == 1
    report_text = report_path.read_text(encoding="utf-8")
    assert "GHSA-jf85-cpcp-j695" in report_text
    assert "dev-host-1" in report_text


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

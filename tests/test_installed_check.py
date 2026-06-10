from unittest.mock import MagicMock
from scripts.lib.types import new_finding
from scripts.installed_check import (
    check_installed_local,
    check_installed_remote_batch,
    apply_installed_demotion,
    apply_installed_checks,
)
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError


def test_npm_installed_true(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.touch()
    (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
    f = new_finding(purl="pkg:npm/lodash@4.17.21", vuln_id="GHSA-1",
                    severity="high", manifest_path=str(lockfile), target="local")
    result = check_installed_local(f)
    assert result["installed"] is True


def test_npm_installed_false(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.touch()
    f = new_finding(purl="pkg:npm/lodash@4.17.21", vuln_id="GHSA-1",
                    severity="high", manifest_path=str(lockfile), target="local")
    result = check_installed_local(f)
    assert result["installed"] is False


def test_scoped_npm_package(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.touch()
    (tmp_path / "node_modules" / "@babel" / "core").mkdir(parents=True)
    f = new_finding(purl="pkg:npm/%40babel/core@7.0", vuln_id="GHSA-3",
                    severity="low", manifest_path=str(lockfile), target="local")
    result = check_installed_local(f)
    assert result["installed"] is True


def test_composer_installed_true(tmp_path):
    lockfile = tmp_path / "composer.lock"
    lockfile.touch()
    (tmp_path / "vendor" / "monolog" / "monolog").mkdir(parents=True)
    f = new_finding(purl="pkg:composer/monolog/monolog@2.0", vuln_id="GHSA-2",
                    severity="medium", manifest_path=str(lockfile), target="local")
    result = check_installed_local(f)
    assert result["installed"] is True


def test_composer_installed_false(tmp_path):
    lockfile = tmp_path / "composer.lock"
    lockfile.touch()
    f = new_finding(purl="pkg:composer/monolog/monolog@2.0", vuln_id="GHSA-2",
                    severity="medium", manifest_path=str(lockfile), target="local")
    result = check_installed_local(f)
    assert result["installed"] is False


def test_pip_finding_skipped():
    f = new_finding(purl="pkg:pypi/requests@2.28", vuln_id="GHSA-4",
                    severity="medium", manifest_path="/a/requirements.txt", target="local")
    result = check_installed_local(f)
    assert "installed" not in result


def test_remote_batch_ssh_error_does_not_set_installed(mocker):
    """SSHUnreachableError during the batch ls -d leaves findings unchanged
    (unknown state — never demote on no evidence)."""
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run_with_rc.side_effect = SSHUnreachableError("unreachable")
    f = new_finding(purl="pkg:npm/lodash@4.17.21", vuln_id="GHSA-1",
                    severity="high", manifest_path="/var/www/package-lock.json", target="mars")
    check_installed_remote_batch([f], mock_runner)
    assert "installed" not in f


def test_remote_batch_pip_not_queried(mocker):
    """Unsupported ecosystems (pip, etc.) have no install path, so the batch
    never queries them and never sets installed."""
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    f = new_finding(purl="pkg:pypi/requests@2.28", vuln_id="GHSA-4",
                    severity="medium", manifest_path="/var/www/requirements.txt", target="mars")
    check_installed_remote_batch([f], mock_runner)
    assert "installed" not in f
    mock_runner.run_with_rc.assert_not_called()


def test_demotion_critical_not_installed():
    f = new_finding(purl="pkg:npm/evil@1.0", vuln_id="MAL-123",
                    severity="critical", manifest_path="/a/package-lock.json", target="local")
    f["installed"] = False
    result = apply_installed_demotion(f)
    assert result["severity"] == "info"
    assert result["original_severity"] == "critical"


def test_demotion_high_not_installed():
    f = new_finding(purl="pkg:npm/bad@1.0", vuln_id="GHSA-1",
                    severity="high", manifest_path="/a/package-lock.json", target="local")
    f["installed"] = False
    result = apply_installed_demotion(f)
    assert result["severity"] == "info"
    assert result["original_severity"] == "high"


def test_no_demotion_when_installed():
    f = new_finding(purl="pkg:npm/vuln@1.0", vuln_id="GHSA-2",
                    severity="critical", manifest_path="/a/package-lock.json", target="local")
    f["installed"] = True
    result = apply_installed_demotion(f)
    assert result["severity"] == "critical"
    assert "original_severity" not in result


def test_no_demotion_medium_not_installed():
    f = new_finding(purl="pkg:npm/meh@1.0", vuln_id="GHSA-3",
                    severity="medium", manifest_path="/a/package-lock.json", target="local")
    f["installed"] = False
    result = apply_installed_demotion(f)
    assert result["severity"] == "medium"
    assert "original_severity" not in result


def test_remote_batch_uses_one_ssh_roundtrip_per_target():
    """Issue #19.1: N findings on one target = ONE ls -d call, not N stats."""
    runner = MagicMock()
    runner.run_with_rc.return_value = (
        "/srv/app/node_modules/lodash\n", 1  # only lodash exists
    )
    findings = [
        new_finding("pkg:npm/lodash@4.17.10", "GHSA-1", "high",
                    "/srv/app/package-lock.json", target="bespin"),
        new_finding("pkg:npm/left-pad@1.0.0", "GHSA-2", "high",
                    "/srv/app/package-lock.json", target="bespin"),
    ]
    check_installed_remote_batch(findings, runner)
    assert runner.run_with_rc.call_count == 1
    cmd = runner.run_with_rc.call_args.args[0]
    assert cmd[:2] == ["ls", "-d"]
    assert findings[0]["installed"] is True
    assert findings[1]["installed"] is False


def test_unified_stage_demotes_local_and_remote_identically(tmp_path):
    """Issue #20.2: identical not-installed findings get the same outcome
    regardless of local vs remote path."""
    lock = tmp_path / "package-lock.json"
    lock.write_text("{}")
    local = new_finding("pkg:npm/left-pad@1.0.0", "GHSA-2", "critical",
                        str(lock), target="local-root")
    remote = new_finding("pkg:npm/left-pad@1.0.0", "GHSA-2", "critical",
                         "/srv/app/package-lock.json", target="bespin")
    runner = MagicMock()
    runner.run_with_rc.return_value = ("", 2)  # nothing installed remotely
    result = apply_installed_checks(
        [local, remote],
        local_manifest_paths={str(lock)},
        remote_runners={"bespin": runner},
    )
    assert result[0]["severity"] == "info" and result[0]["original_severity"] == "critical"
    assert result[1]["severity"] == "info" and result[1]["original_severity"] == "critical"


def test_unified_stage_skips_status_records():
    err = new_finding("pkg:scan-error/bespin@-", "SCAN_ERROR", "info",
                      "/x/package-lock.json", target="bespin", status="SCAN_ERROR")
    runner = MagicMock()
    apply_installed_checks([err], local_manifest_paths=set(),
                           remote_runners={"bespin": runner})
    runner.run_with_rc.assert_not_called()
    assert "installed" not in err

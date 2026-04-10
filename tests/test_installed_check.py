import pytest
from pathlib import Path
from scripts.lib.types import new_finding
from scripts.installed_check import (
    check_installed_local,
    check_installed_remote,
    apply_installed_demotion,
    apply_installed_checks_local,
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


def test_remote_npm_installed_true(mocker):
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run_with_rc.return_value = ("/var/www/node_modules/lodash\n", 0)
    f = new_finding(purl="pkg:npm/lodash@4.17.21", vuln_id="GHSA-1",
                    severity="high", manifest_path="/var/www/package-lock.json", target="mars")
    result = check_installed_remote(f, mock_runner)
    assert result["installed"] is True


def test_remote_npm_installed_false(mocker):
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run_with_rc.return_value = ("", 1)
    f = new_finding(purl="pkg:npm/lodash@4.17.21", vuln_id="GHSA-1",
                    severity="high", manifest_path="/var/www/package-lock.json", target="mars")
    result = check_installed_remote(f, mock_runner)
    assert result["installed"] is False


def test_remote_ssh_error_does_not_set_installed(mocker):
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run_with_rc.side_effect = SSHUnreachableError("unreachable")
    f = new_finding(purl="pkg:npm/lodash@4.17.21", vuln_id="GHSA-1",
                    severity="high", manifest_path="/var/www/package-lock.json", target="mars")
    result = check_installed_remote(f, mock_runner)
    assert "installed" not in result


def test_remote_pip_skipped(mocker):
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    f = new_finding(purl="pkg:pypi/requests@2.28", vuln_id="GHSA-4",
                    severity="medium", manifest_path="/var/www/requirements.txt", target="mars")
    result = check_installed_remote(f, mock_runner)
    assert "installed" not in result
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

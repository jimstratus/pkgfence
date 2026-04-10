"""Tests for EOL software detection via curated catalog."""
import pytest
from pathlib import Path
from scripts.eol_detect import load_eol_catalog, detect_eol_local, detect_eol_remote
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError


def test_catalog_loads():
    catalog = load_eol_catalog()
    assert len(catalog) > 0
    assert catalog[0]["name"] == "Pydio"


def test_detect_pydio_eol(tmp_path):
    pydio_dir = tmp_path / "apps" / "pydio"
    pydio_dir.mkdir(parents=True)
    (pydio_dir / "base.conf.php").touch()
    version_dir = pydio_dir / "conf"
    version_dir.mkdir()
    (version_dir / "VERSION").write_text("8.2.5")
    findings = detect_eol_local([str(tmp_path)])
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "EOL-Pydio-8.2.5"
    assert findings[0]["severity"] == "high"
    assert findings[0]["installed"] is True


def test_detect_pydio_not_eol(tmp_path):
    pydio_dir = tmp_path / "apps" / "pydio"
    pydio_dir.mkdir(parents=True)
    (pydio_dir / "base.conf.php").touch()
    version_dir = pydio_dir / "conf"
    version_dir.mkdir()
    (version_dir / "VERSION").write_text("9.1.0")
    findings = detect_eol_local([str(tmp_path)])
    assert len(findings) == 0


def test_wordpress_null_eol_before_no_finding(tmp_path):
    wp_dir = tmp_path / "httpdocs"
    wp_includes = wp_dir / "wp-includes"
    wp_includes.mkdir(parents=True)
    (wp_includes / "version.php").write_text("<?php\n$wp_version = '6.4.3';\n")
    findings = detect_eol_local([str(tmp_path)])
    assert len(findings) == 0  # eol_before is null


def test_no_detection_in_empty_dir(tmp_path):
    findings = detect_eol_local([str(tmp_path)])
    assert findings == []


def test_detect_eol_remote_pydio(mocker):
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run.side_effect = [
        "/var/www/apps/pydio/base.conf.php\n",  # find result
        "8.2.5\n",                                # cat conf/VERSION
    ]
    findings = detect_eol_remote(
        discover_paths=["/var/www"],
        runner=mock_runner,
        target_name="mars",
        target_host="mars.example.com",
    )
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "EOL-Pydio-8.2.5"
    assert findings[0]["target"] == "mars"
    assert findings[0]["severity"] == "high"


def test_detect_eol_remote_no_matches(mocker):
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run.return_value = ""  # find returns nothing
    findings = detect_eol_remote(
        discover_paths=["/var/www"],
        runner=mock_runner,
        target_name="clean-host",
        target_host="10.0.0.1",
    )
    assert findings == []


def test_detect_eol_remote_ssh_error(mocker):
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run.side_effect = SSHUnreachableError("unreachable")
    findings = detect_eol_remote(
        discover_paths=["/var/www"],
        runner=mock_runner,
        target_name="down-host",
        target_host="10.0.0.2",
    )
    assert findings == []

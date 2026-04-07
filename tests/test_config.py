"""Test the defaults.yaml loader."""
import pytest
from scripts.lib.config import load_defaults, DefaultsError


def test_load_defaults_returns_expected_keys():
    cfg = load_defaults()
    assert "severity" in cfg
    assert "scanners" in cfg
    assert "threat_intel" in cfg
    assert "reports" in cfg
    assert "exit_codes" in cfg
    assert cfg["severity"]["fail_threshold"] == "critical"
    assert cfg["threat_intel"]["cache_ttls"]["kev"] == "24h"
    assert cfg["reports"]["calibrated_trust_disclaimer"] is True


def test_load_defaults_exit_codes_are_integers():
    cfg = load_defaults()
    assert cfg["exit_codes"]["clean"] == 0
    assert cfg["exit_codes"]["findings"] == 1
    assert cfg["exit_codes"]["scanner_error"] == 2
    assert cfg["exit_codes"]["config_error"] == 3

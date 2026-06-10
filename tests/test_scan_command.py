"""End-to-end tests for scripts.scan_command.run_scan().
Mocks scanner invocation; verifies the L1->L2->L3->L4->output pipeline wires correctly."""
from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import pytest

from scripts.lib.types import new_finding


def _write_registry(reg_path: Path, workspace: Path) -> None:
    """Write a minimal registry YAML pointing at workspace as a single root.

    Uses forward-slash path to keep YAML string parsing happy on Windows.
    """
    ws_str = str(workspace).replace("\\", "/")
    reg_path.write_text(
        "version: 1\n"
        "roots:\n"
        f"  - path: '{ws_str}'\n"
        "    tier: 1\n"
        "projects: []\n"
        "ssh: []\n"
        "github: []\n",
        encoding="utf-8",
    )


def test_run_scan_end_to_end_with_npm_fixture(tmp_path, tmp_state):
    """Wire L1->L2->L3->L4->output and verify a known-vulnerable npm fixture
    produces a report with the expected vuln."""
    workspace = tmp_path / "workspace"
    proj = workspace / "vuln-proj"
    proj.mkdir(parents=True)
    (proj / "package-lock.json").write_text(
        '{"name":"v","version":"1.0.0","lockfileVersion":3,'
        '"packages":{"":{"name":"v","version":"1.0.0"},'
        '"node_modules/lodash":{"version":"4.17.10"}}}'
    )
    (proj / "node_modules" / "lodash").mkdir(parents=True)

    reg = tmp_path / "registry.yaml"
    _write_registry(reg, workspace)

    fake_finding = new_finding(
        purl="pkg:npm/lodash@4.17.10",
        vuln_id="GHSA-jf85-cpcp-j695",
        severity="high",
        manifest_path=str(proj / "package-lock.json"),
        target=workspace.name,
        description="Prototype Pollution in lodash",
    )

    from scripts.scan_command import run_scan

    with patch("scripts.scan_command.scan_all_manifests", return_value=[fake_finding]):
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
    assert report_path.exists()
    report_text = report_path.read_text(encoding="utf-8")
    assert "GHSA-jf85-cpcp-j695" in report_text
    assert "Calibrated trust disclaimer" in report_text


def test_run_scan_clean_exit_zero(tmp_path, tmp_state):
    """When no findings -> exit code 0."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    reg = tmp_path / "registry.yaml"
    _write_registry(reg, workspace)

    from scripts.scan_command import run_scan

    with patch("scripts.scan_command.scan_all_manifests", return_value=[]):
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
                exit_code, report_path = run_scan(registry_path=reg, state_dir=tmp_state)

    assert exit_code == 0
    assert report_path.exists()


def test_exit_code_3_on_invalid_registry(tmp_path, tmp_state):
    """Configuration error -> exit 3."""
    reg = tmp_path / "registry.yaml"
    reg.write_text("not valid yaml: [unclosed")

    from scripts.scan_command import run_scan

    exit_code, _ = run_scan(registry_path=reg, state_dir=tmp_state)
    assert exit_code == 3


def test_exit_code_1_when_high_finding_with_default_fail_on_critical(tmp_path, tmp_state):
    """HIGH severity finding + fail_on=critical -> exit 0 (high is below floor).
    HIGH severity finding + fail_on=high -> exit 1."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    reg = tmp_path / "registry.yaml"
    _write_registry(reg, workspace)

    fake_finding = new_finding(
        purl="pkg:npm/lodash@4.17.10",
        vuln_id="GHSA-x",
        severity="high",
        manifest_path=str(workspace / "package-lock.json"),
        target="workspace",
    )

    from scripts.scan_command import run_scan

    with patch("scripts.scan_command.scan_all_manifests", return_value=[fake_finding]):
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
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

                # fail_on=critical -> high finding does not trigger exit 1
                exit0, _ = run_scan(registry_path=reg, state_dir=tmp_state, fail_on="critical")
                # fail_on=high -> high finding does trigger exit 1
                exit1, _ = run_scan(registry_path=reg, state_dir=tmp_state, fail_on="high")

    assert exit0 == 0
    assert exit1 == 1


def test_run_scan_with_adhoc_path(tmp_path, tmp_state):
    """--path bypasses the registry entirely and scans an arbitrary directory."""
    workspace = tmp_path / "ad-hoc"
    workspace.mkdir()
    proj = workspace / "newproj"
    proj.mkdir()
    (proj / "package-lock.json").write_text("{}")
    (proj / "node_modules" / "foo").mkdir(parents=True)

    fake_finding = new_finding(
        purl="pkg:npm/foo@1.0",
        vuln_id="GHSA-y",
        severity="high",
        manifest_path=str(proj / "package-lock.json"),
        target="ad-hoc",
    )

    from scripts.scan_command import run_scan

    with patch("scripts.scan_command.scan_all_manifests", return_value=[fake_finding]):
        with patch("scripts.scan_command.KEVClient") as mock_kev_cls:
            mock_kev = MagicMock()
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

                # No registry path passed; adhoc_path provided
                exit_code, report_path = run_scan(
                    registry_path=Path("does-not-exist.yaml"),
                    state_dir=tmp_state,
                    adhoc_path=workspace,
                    fail_on="high",
                )

    assert exit_code == 1
    assert report_path.exists()


def test_degraded_enricher_adds_exactly_one_message(tmp_state, tmp_registry):
    """Issue #20.1: each degraded feed contributes exactly one degraded-mode
    line, via the shared enricher loop (no ad-hoc dedup hacks)."""
    from scripts.scan_command import run_scan

    with patch("scripts.scan_command.KEVClient") as kev_cls, \
         patch("scripts.scan_command.EPSSClient") as epss_cls:
        kev_cls.return_value.is_degraded = True
        kev_cls.return_value.is_stale = False
        epss_cls.return_value.is_degraded = True
        epss_cls.return_value.is_stale = False
        epss_cls.return_value.feed_timestamp = None
        exit_code, report_path = run_scan(tmp_registry, tmp_state)
    report = report_path.read_text(encoding="utf-8")
    # Each message renders exactly TWICE: once in the YAML frontmatter
    # degraded_modes list, once in the body's degraded-mode section.
    assert report.count("CISA KEV feed degraded") == 2
    assert report.count("EPSS feed degraded") == 2


def test_stale_enricher_emits_stale_message(tmp_state, tmp_registry):
    """The enricher loop's stale branch (elif) emits the stale message when
    a feed served an expired cache rather than degrading outright (#20.1)."""
    from scripts.scan_command import run_scan

    with patch("scripts.scan_command.KEVClient") as kev_cls, \
         patch("scripts.scan_command.EPSSClient") as epss_cls:
        kev_cls.return_value.is_degraded = False
        kev_cls.return_value.is_stale = True
        epss_cls.return_value.is_degraded = False
        epss_cls.return_value.is_stale = False
        epss_cls.return_value.feed_timestamp = None
        _exit_code, report_path = run_scan(tmp_registry, tmp_state)
    report = report_path.read_text(encoding="utf-8")
    assert "CISA KEV feed stale" in report
    assert "CISA KEV feed degraded" not in report

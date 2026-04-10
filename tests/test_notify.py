"""Tests for scripts/notify.py — pkgfence-notify subcommand."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.notify import (
    parse_report_frontmatter,
    get_two_latest_reports,
    check_for_new_findings,
    send_webhook,
    format_stdout_summary,
    main,
)


def _write_report(state_dir, run_id, findings_by_severity, targets=None):
    reports_dir = state_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    fm = f"---\nrun_id: {run_id}\ntimestamp: '2026-04-10T12:00:00Z'\nscanner_host: SCANHOST\nfindings_total: {sum(findings_by_severity.values())}\nfindings_by_severity:\n"
    for sev, count in findings_by_severity.items():
        fm += f"  {sev}: {count}\n"
    fm += f"ssh_targets: {json.dumps(targets or [])}\nlocal_roots: []\n---\n\n# Report\n"
    (reports_dir / f"{run_id}.md").write_text(fm)


def test_parse_report_frontmatter(tmp_path):
    """parse_report_frontmatter extracts YAML between --- markers."""
    _write_report(tmp_path, "20260410T060000Z-aaa", {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})
    report_path = tmp_path / "reports" / "20260410T060000Z-aaa.md"
    fm = parse_report_frontmatter(report_path)
    assert fm["run_id"] == "20260410T060000Z-aaa"
    assert fm["scanner_host"] == "SCANHOST"
    assert fm["findings_by_severity"]["critical"] == 1
    assert fm["findings_total"] == 1


def test_notify_no_new_findings(tmp_path):
    """Same counts in both reports → not triggered."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0})
    result = check_for_new_findings(tmp_path, threshold="critical")
    assert result["triggered"] is False
    assert result["new_findings"]["critical"] == 0
    assert result["new_findings"]["high"] == 0


def test_notify_new_critical(tmp_path):
    """New critical finding → triggered."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 0, "high": 0, "medium": 2, "low": 3, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 1, "high": 0, "medium": 2, "low": 3, "info": 0})
    result = check_for_new_findings(tmp_path, threshold="critical")
    assert result["triggered"] is True
    assert result["new_findings"]["critical"] == 1
    assert result["run_id"] == "20260410T060000Z-bbb"
    assert result["previous_run_id"] == "20260409T060000Z-aaa"


def test_notify_threshold_high(tmp_path):
    """New high finding with threshold=high → triggered."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0})
    result = check_for_new_findings(tmp_path, threshold="high")
    assert result["triggered"] is True
    assert result["new_findings"]["high"] == 2


def test_notify_threshold_high_does_not_trigger_on_low(tmp_path):
    """New low finding with threshold=high → not triggered."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 0, "high": 0, "medium": 0, "low": 5, "info": 0})
    result = check_for_new_findings(tmp_path, threshold="high")
    assert result["triggered"] is False


def test_notify_only_one_report(tmp_path):
    """Only one report → not triggered (no comparison possible)."""
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})
    result = check_for_new_findings(tmp_path, threshold="critical")
    assert result["triggered"] is False


def test_notify_no_reports(tmp_path):
    """Zero reports → not triggered."""
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    result = check_for_new_findings(tmp_path, threshold="critical")
    assert result["triggered"] is False


def test_notify_clamped_to_zero(tmp_path):
    """Decreased counts do not go negative — clamped to 0."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 5, "high": 0, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 2, "high": 0, "medium": 0, "low": 0, "info": 0})
    result = check_for_new_findings(tmp_path, threshold="critical")
    assert result["triggered"] is False
    assert result["new_findings"]["critical"] == 0


def test_webhook_payload(tmp_path):
    """send_webhook posts correct JSON payload via httpx."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 1, "high": 0, "medium": 2, "low": 3, "info": 0}, targets=["mars", "bespin"])
    result = check_for_new_findings(tmp_path, threshold="critical")

    from scripts.notify import _build_webhook_payload
    payload = _build_webhook_payload(result, "critical")

    with patch("scripts.notify.httpx.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200)
        send_webhook("https://n8n.example.com/webhook/pkgfence", payload)

    assert mock_post.called
    call_kwargs = mock_post.call_args
    url = call_kwargs.args[0] if call_kwargs.args else call_kwargs.kwargs.get("url")
    payload = call_kwargs.kwargs.get("json") or call_kwargs.args[1]
    assert url == "https://n8n.example.com/webhook/pkgfence"
    assert payload["event"] == "pkgfence.scan.new_findings"
    assert payload["run_id"] == "20260410T060000Z-bbb"
    assert payload["previous_run_id"] == "20260409T060000Z-aaa"
    assert "new_findings" in payload
    assert "timestamp" in payload
    assert "scanner_host" in payload
    assert "threshold" in payload


def test_webhook_failure_does_not_raise(tmp_path):
    """httpx.post raising → logged as warning, no exception propagated."""
    import httpx

    result = {
        "triggered": True,
        "new_findings": {"critical": 1},
        "run_id": "20260410T060000Z-bbb",
        "previous_run_id": "20260409T060000Z-aaa",
        "targets": [],
        "summary": "1 new critical finding(s)",
        "threshold": "critical",
    }

    with patch("scripts.notify.httpx.post", side_effect=httpx.RequestError("connection refused", request=MagicMock())):
        # Must not raise
        send_webhook("https://n8n.example.com/webhook/pkgfence", result)


def test_format_stdout_summary_not_triggered():
    """format_stdout_summary returns a human-readable string when not triggered."""
    result = {
        "triggered": False,
        "new_findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "run_id": "20260410T060000Z-bbb",
        "previous_run_id": "20260409T060000Z-aaa",
        "targets": ["mars"],
        "summary": "No new findings above threshold",
        "threshold": "critical",
    }
    text = format_stdout_summary(result)
    assert isinstance(text, str)
    assert len(text) > 0
    assert "20260410T060000Z-bbb" in text


def test_format_stdout_summary_triggered():
    """format_stdout_summary flags triggered state clearly."""
    result = {
        "triggered": True,
        "new_findings": {"critical": 1, "high": 0, "medium": 2, "low": 3, "info": 0},
        "run_id": "20260410T060000Z-bbb",
        "previous_run_id": "20260409T060000Z-aaa",
        "targets": ["mars", "bespin"],
        "summary": "1 new critical finding(s) since 20260409T060000Z",
        "threshold": "critical",
    }
    text = format_stdout_summary(result)
    assert "20260410T060000Z-bbb" in text
    assert "critical" in text.lower()


def test_main_exit_0_when_not_triggered(tmp_path):
    """main() returns 0 when no new findings above threshold."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})
    rc = main(["--state", str(tmp_path)])
    assert rc == 0


def test_main_exit_1_when_triggered(tmp_path):
    """main() returns 1 when new findings appear above threshold."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})
    rc = main(["--state", str(tmp_path)])
    assert rc == 1


def test_main_posts_webhook_when_triggered(tmp_path):
    """main() POSTs to webhook URL when triggered and --webhook is set."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})

    with patch("scripts.notify.httpx.post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200)
        rc = main(["--state", str(tmp_path), "--webhook", "https://n8n.example.com/webhook/test"])

    assert rc == 1
    assert mock_post.called


def test_main_no_webhook_when_not_triggered(tmp_path):
    """main() does NOT call webhook when not triggered, even if --webhook is set."""
    _write_report(tmp_path, "20260409T060000Z-aaa", {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})

    with patch("scripts.notify.httpx.post") as mock_post:
        rc = main(["--state", str(tmp_path), "--webhook", "https://n8n.example.com/webhook/test"])

    assert rc == 0
    mock_post.assert_not_called()


def test_get_two_latest_reports_returns_none_when_fewer_than_two(tmp_path):
    """get_two_latest_reports returns None when fewer than 2 reports exist."""
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    assert get_two_latest_reports(tmp_path) is None
    _write_report(tmp_path, "20260410T060000Z-bbb", {"critical": 0})
    assert get_two_latest_reports(tmp_path) is None


def test_get_two_latest_reports_returns_previous_and_current(tmp_path):
    """get_two_latest_reports returns (previous, current) sorted by filename."""
    _write_report(tmp_path, "20260408T060000Z-111", {"critical": 0})
    _write_report(tmp_path, "20260409T060000Z-222", {"critical": 0})
    _write_report(tmp_path, "20260410T060000Z-333", {"critical": 0})
    pair = get_two_latest_reports(tmp_path)
    assert pair is not None
    prev, curr = pair
    assert prev.name == "20260409T060000Z-222.md"
    assert curr.name == "20260410T060000Z-333.md"

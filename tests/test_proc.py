"""Tests for the shared subprocess wrapper."""
from unittest.mock import patch

from scripts.lib.proc import run_capture


def test_run_capture_pins_utf8_and_capture_flags():
    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        run_capture(["echo", "hi"], timeout=5)
    kwargs = mock_run.call_args.kwargs
    assert kwargs["encoding"] == "utf-8"
    assert kwargs["errors"] == "replace"
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["check"] is False
    assert kwargs["timeout"] == 5

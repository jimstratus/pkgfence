"""Test the logger factory produces a properly-configured logger."""
import logging
from scripts.lib.logger import get_logger


def test_get_logger_returns_named_logger():
    log = get_logger("scripts.lib.foo")
    assert isinstance(log, logging.Logger)
    assert log.name == "scripts.lib.foo"


def test_get_logger_caches_by_name():
    a = get_logger("scripts.lib.foo")
    b = get_logger("scripts.lib.foo")
    assert a is b  # Python's logging module caches by name

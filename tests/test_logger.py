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


def test_module_loggers_route_via_scripts_ancestor():
    """Hierarchy fix: handlers live on the 'scripts' ancestor so scripts.*
    module loggers (e.g. scripts.eol_detect) propagate to them — not on a
    'pkgfence' sibling, which module loggers would never reach."""
    get_logger("scripts.eol_detect")  # ensures _configure_once has run
    scripts_logger = logging.getLogger("scripts")
    pkgfence_logger = logging.getLogger("pkgfence")
    assert any(isinstance(h, logging.FileHandler) for h in scripts_logger.handlers), (
        "scripts ancestor must hold the file handler"
    )
    assert pkgfence_logger.handlers == [], (
        "pkgfence sibling must hold no handlers (module logs would never reach it)"
    )

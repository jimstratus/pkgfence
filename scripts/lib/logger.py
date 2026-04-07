"""Centralized logging factory for pkgfence.

All modules get loggers via get_logger(__name__). The factory configures
file + stderr handlers once at first use. Log file lives in state/logs/
which is gitignored.

Use:
    from scripts.lib.logger import get_logger
    log = get_logger(__name__)
    log.info("scan starting", extra={"target": target})
"""
import logging
import os
from pathlib import Path


_configured = False


def _configure_once() -> None:
    global _configured
    if _configured:
        return
    state_dir = Path(os.environ.get("PKGFENCE_STATE", "state"))
    log_dir = state_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger("pkgfence")
    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = logging.FileHandler(
        log_dir / "pkgfence.log", encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(fmt)
    root.addHandler(stream_handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger for the given module name. Configures on first call."""
    _configure_once()
    return logging.getLogger(name)

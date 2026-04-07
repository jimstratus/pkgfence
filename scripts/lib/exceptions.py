"""Expiring exceptions/waivers for the triage layer.

Each exception suppresses findings matching (vuln_id, scope) until expires
date. Expiry is mandatory — no indefinite waivers.
"""
import datetime
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError


_yaml = YAML(typ="safe")


class ExceptionsError(Exception):
    pass


def load_exceptions(path: Path) -> list[dict[str, Any]]:
    """Load exceptions from a YAML file. Returns [] if file doesn't exist
    (no exceptions = empty list, not an error)."""
    if not path.exists():
        return []
    try:
        data = _yaml.load(path.read_text(encoding="utf-8"))
    except YAMLError as e:
        raise ExceptionsError(f"Exceptions YAML parse error in {path}: {e}") from e
    if data is None:
        return []
    if not isinstance(data, list):
        raise ExceptionsError(f"Exceptions file must be a list, got {type(data).__name__}")
    return data


def is_exception_active(exception: dict, today: datetime.date | None = None) -> bool:
    """An exception is active if it has an 'expires' field and that date
    is in the future relative to `today` (default: actual today)."""
    if today is None:
        today = datetime.date.today()
    expires = exception.get("expires")
    if not expires:
        return False
    if isinstance(expires, str):
        try:
            expires = datetime.date.fromisoformat(expires)
        except ValueError:
            return False
    elif isinstance(expires, datetime.datetime):
        expires = expires.date()
    return expires >= today

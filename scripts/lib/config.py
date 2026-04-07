"""Defaults loader for pkgfence.

Every module that needs a default value imports this rather than hardcoding.
Values flow from config/defaults.yaml (committed, versioned) and can later
be overlaid by state/overrides.yaml (user-local, uncommitted) in Phase 2+.
"""
from functools import lru_cache
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError


SKILL_ROOT = Path(__file__).parent.parent.parent
DEFAULTS_PATH = SKILL_ROOT / "config" / "defaults.yaml"

_yaml_loader = YAML(typ="safe")


class DefaultsError(Exception):
    pass


@lru_cache(maxsize=1)
def load_defaults() -> dict[str, Any]:
    """Load and cache config/defaults.yaml. Raises DefaultsError on parse failure."""
    if not DEFAULTS_PATH.exists():
        raise DefaultsError(f"Defaults file not found: {DEFAULTS_PATH}")
    try:
        return _yaml_loader.load(DEFAULTS_PATH.read_text())
    except YAMLError as e:
        raise DefaultsError(f"Defaults parse error: {e}") from e

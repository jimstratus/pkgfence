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


def load_yaml(path: Path) -> Any:
    """Load a YAML file with the safe loader. Raises YAMLError on parse
    failure — each caller decides its own policy (strict for defaults,
    tolerant for exclusions). Returns None for an empty file.

    NOT for files that get round-tripped back to disk (registry) — those
    need YAML(typ='rt') to preserve key order and comments."""
    return _yaml_loader.load(Path(path).read_text(encoding="utf-8"))


class DefaultsError(Exception):
    pass


@lru_cache(maxsize=1)
def load_defaults() -> dict[str, Any]:
    """Load and cache config/defaults.yaml. Raises DefaultsError on parse failure."""
    if not DEFAULTS_PATH.exists():
        raise DefaultsError(f"Defaults file not found: {DEFAULTS_PATH}")
    try:
        return load_yaml(DEFAULTS_PATH)
    except YAMLError as e:
        raise DefaultsError(f"Defaults parse error: {e}") from e

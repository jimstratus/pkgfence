"""Registry loading, validation, and atomic writes."""
from pathlib import Path
from typing import Any
import os
import tempfile

import jsonschema
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError


SKILL_ROOT = Path(__file__).parent.parent.parent
SCHEMA_PATH = SKILL_ROOT / "config" / "registry.schema.yaml"


class RegistryError(Exception):
    """Raised on registry parse, schema, or atomic-write failures."""


_yaml = YAML(typ="rt")  # round-trip preserves comments
_yaml.preserve_quotes = True

# Separate safe loader for the schema file (no comment preservation needed)
_yaml_safe = YAML(typ="safe")


def _load_schema() -> dict:
    return _yaml_safe.load(SCHEMA_PATH.read_text())


def load_registry(path: Path) -> dict[str, Any]:
    """Load a registry.yaml file and validate against the schema.
    Raises RegistryError on parse or schema failure with a clear message."""
    if not path.exists():
        raise RegistryError(f"Registry not found: {path}")
    try:
        data = _yaml.load(path.read_text())
    except YAMLError as e:
        raise RegistryError(f"Registry YAML parse error in {path}: {e}") from e
    if data is None:
        raise RegistryError(f"Registry is empty: {path}")
    schema = _load_schema()
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        raise RegistryError(
            f"Registry schema error in {path} at {list(e.absolute_path)}: {e.message}"
        ) from e
    return data


def save_registry_atomic(path: Path, data: dict[str, Any]) -> None:
    """Atomic write: validate -> write to temp-file in same dir -> os.replace.

    os.replace() is atomic on both Windows and POSIX when source and destination
    are on the same filesystem. We place the temp file in path.parent to
    guarantee that. No cross-filesystem writes.

    We DO NOT use portalocker here for MVP. Cross-writer serialization would
    require locking a dedicated lock file - overkill for Phase 1 where pkgfence
    has one writer (scan or watch). Revisit when a second writer appears
    (e.g., multiple concurrent `registry add-*` subcommands).

    Never leaves the registry empty during a write (temp file pattern guarantees that).
    """
    schema = _load_schema()
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        raise RegistryError(
            f"Refusing to save invalid registry: {e.message}"
        ) from e

    fd, tmp = tempfile.mkstemp(
        prefix=".registry.", suffix=".yaml.tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            _yaml.dump(data, f)
        os.replace(tmp, path)  # atomic rename; path is never empty
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

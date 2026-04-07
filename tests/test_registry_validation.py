"""Tests for registry schema validation."""
import pytest
from pathlib import Path
from ruamel.yaml import YAML
import jsonschema

SKILL_ROOT = Path(__file__).parent.parent
SCHEMA_PATH = SKILL_ROOT / "config" / "registry.schema.yaml"

# Use the same loader as scripts/lib/registry.py to keep dep tree to 4 pinned deps
_yaml_loader = YAML(typ="safe")


def load_schema():
    return _yaml_loader.load(SCHEMA_PATH.read_text())


def test_minimal_valid_registry_passes():
    schema = load_schema()
    minimal = {
        "version": 1,
        "roots": [],
        "projects": [],
        "ssh": [],
        "github": [],
    }
    jsonschema.validate(instance=minimal, schema=schema)  # raises if invalid


def test_root_with_required_fields_passes():
    schema = load_schema()
    config = {
        "version": 1,
        "roots": [
            {
                "path": "D:\\projects",
                "tier": 1,
                "exclude": [".git", "node_modules"],
                "monorepo_mode": "per_package",
            }
        ],
        "projects": [],
        "ssh": [],
        "github": [],
    }
    jsonschema.validate(instance=config, schema=schema)


def test_missing_version_field_raises():
    schema = load_schema()
    bad = {"roots": [], "projects": [], "ssh": [], "github": []}
    with pytest.raises(jsonschema.ValidationError, match="version"):
        jsonschema.validate(instance=bad, schema=schema)


def test_invalid_tier_value_raises():
    schema = load_schema()
    bad = {
        "version": 1,
        "roots": [{"path": "D:\\foo", "tier": 99}],  # only 1-3 allowed
        "projects": [],
        "ssh": [],
        "github": [],
    }
    with pytest.raises(jsonschema.ValidationError, match="tier"):
        jsonschema.validate(instance=bad, schema=schema)


def test_unknown_field_at_top_level_raises():
    """M2 fix: verify additionalProperties: false is actually enforced.
    A silent relax of additionalProperties would be a regression vector."""
    schema = load_schema()
    bad = {
        "version": 1,
        "roots": [],
        "projects": [],
        "ssh": [],
        "github": [],
        "mystery_field": "should be rejected",
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=bad, schema=schema)


def test_unknown_field_in_root_raises():
    """Same enforcement check at the roots[] item level."""
    schema = load_schema()
    bad = {
        "version": 1,
        "roots": [{"path": "D:\\foo", "tier": 1, "mystery": "reject me"}],
        "projects": [],
        "ssh": [],
        "github": [],
    }
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=bad, schema=schema)

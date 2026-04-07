"""Shared pytest fixtures for pkgfence tests."""
import pytest
from pathlib import Path
import tempfile


@pytest.fixture
def tmp_state(tmp_path: Path) -> Path:
    """Provide an isolated state/ directory for tests."""
    state = tmp_path / "state"
    state.mkdir()
    (state / "cache").mkdir()
    (state / "baselines").mkdir()
    (state / "reports").mkdir()
    (state / "audit.jsonl.d").mkdir()
    return state


@pytest.fixture
def tmp_registry(tmp_path: Path) -> Path:
    """Provide an empty registry.yaml file for tests."""
    registry = tmp_path / "registry.yaml"
    registry.write_text("version: 1\nroots: []\nprojects: []\nssh: []\ngithub: []\n")
    return registry

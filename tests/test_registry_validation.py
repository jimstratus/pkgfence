"""Tests for registry schema validation."""
import pytest
import subprocess
import sys
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


from scripts.lib.registry import load_registry, RegistryError


def test_load_valid_registry(tmp_path):
    reg_path = tmp_path / "registry.yaml"
    # Use double-quoted YAML so escape semantics are explicit:
    # "D:\\\\projects" in Python is the 4-char string D:\\projects,
    # which YAML double-quoted parses as the 2-char path D:\projects.
    reg_path.write_text("""
version: 1
roots:
  - path: "D:\\\\projects"
    tier: 1
projects: []
ssh: []
github: []
""")
    reg = load_registry(reg_path)
    assert reg["version"] == 1
    assert reg["roots"][0]["path"] == "D:\\projects"


def test_load_invalid_registry_raises(tmp_path):
    reg_path = tmp_path / "registry.yaml"
    reg_path.write_text("not valid yaml: [unclosed")
    with pytest.raises(RegistryError):
        load_registry(reg_path)


def test_load_missing_version_raises(tmp_path):
    reg_path = tmp_path / "registry.yaml"
    reg_path.write_text("roots: []\nprojects: []\nssh: []\ngithub: []\n")
    with pytest.raises(RegistryError, match="version"):
        load_registry(reg_path)


def test_example_registry_validates():
    example = SKILL_ROOT / "config" / "registry.example.yaml"
    reg = load_registry(example)
    assert reg["version"] == 1
    assert len(reg["roots"]) > 0


def test_registry_cli_validate_passes_on_valid(tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text("version: 1\nroots: []\nprojects: []\nssh: []\ngithub: []\n")
    result = subprocess.run(
        [sys.executable, "-m", "scripts.registry_cli", "--registry", str(reg), "validate"],
        capture_output=True, text=True, cwd=str(SKILL_ROOT),
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    assert "OK" in result.stdout


def test_registry_cli_validate_fails_on_invalid(tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text("not valid yaml: [unclosed")
    result = subprocess.run(
        [sys.executable, "-m", "scripts.registry_cli", "--registry", str(reg), "validate"],
        capture_output=True, text=True, cwd=str(SKILL_ROOT),
    )
    assert result.returncode == 3  # configuration error
    assert "error" in result.stderr.lower()


def test_registry_cli_add_root(tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text("version: 1\nroots: []\nprojects: []\nssh: []\ngithub: []\n")
    result = subprocess.run(
        [sys.executable, "-m", "scripts.registry_cli",
         "--registry", str(reg),
         "add-root", "D:\\projects", "--tier", "1"],
        capture_output=True, text=True, cwd=str(SKILL_ROOT),
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    reg_data = load_registry(reg)
    assert any(r["path"] == "D:\\projects" for r in reg_data["roots"])


def test_registry_cli_add_project(tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text("version: 1\nroots: []\nprojects: []\nssh: []\ngithub: []\n")
    result = subprocess.run(
        [sys.executable, "-m", "scripts.registry_cli",
         "--registry", str(reg),
         "add-project", "C:\\eotir", "--name", "eotir-main", "--tier", "1"],
        capture_output=True, text=True, cwd=str(SKILL_ROOT),
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    reg_data = load_registry(reg)
    assert any(p["name"] == "eotir-main" for p in reg_data["projects"])
    assert reg_data["projects"][0]["path"] == "C:\\eotir"


def test_registry_cli_remove_root(tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text("""version: 1
roots:
  - {path: "D:\\\\projects", tier: 1}
  - {path: "C:\\\\eotir\\\\projects", tier: 1}
projects: []
ssh: []
github: []
""")
    result = subprocess.run(
        [sys.executable, "-m", "scripts.registry_cli",
         "--registry", str(reg),
         "remove", "D:\\projects"],
        capture_output=True, text=True, cwd=str(SKILL_ROOT),
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    reg_data = load_registry(reg)
    assert len(reg_data["roots"]) == 1
    assert reg_data["roots"][0]["path"] == "C:\\eotir\\projects"


def test_registry_cli_remove_project(tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text("""version: 1
roots: []
projects:
  - {path: "C:\\\\eotir", name: eotir-main, tier: 1}
ssh: []
github: []
""")
    result = subprocess.run(
        [sys.executable, "-m", "scripts.registry_cli",
         "--registry", str(reg),
         "remove", "eotir-main"],
        capture_output=True, text=True, cwd=str(SKILL_ROOT),
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    reg_data = load_registry(reg)
    assert len(reg_data["projects"]) == 0


def test_registry_cli_remove_nonexistent_fails(tmp_path):
    reg = tmp_path / "registry.yaml"
    reg.write_text("version: 1\nroots: []\nprojects: []\nssh: []\ngithub: []\n")
    result = subprocess.run(
        [sys.executable, "-m", "scripts.registry_cli",
         "--registry", str(reg),
         "remove", "does-not-exist"],
        capture_output=True, text=True, cwd=str(SKILL_ROOT),
    )
    assert result.returncode == 3
    assert "not found" in result.stderr.lower()


def test_ssh_entry_accepts_optional_key_file(tmp_path):
    """ssh items may optionally include a key_file path (for -i <path>)."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: dev-host-1\n"
        "    host: 192.0.2.10\n"
        "    user: devuser\n"
        "    key_file: ~/.ssh/lab-key\n"
        "    tier: 2\n"
        "github: []\n"
    )
    data = load_registry(reg)
    assert data["ssh"][0]["key_file"] == "~/.ssh/lab-key"


def test_ssh_entry_without_key_file_still_valid(tmp_path):
    """ssh items without key_file must remain valid (fall back to ~/.ssh/config)."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: mars\n"
        "    host: mars.example\n"
        "    user: scanuser\n"
        "    tier: 1\n"
        "github: []\n"
    )
    data = load_registry(reg)
    assert "key_file" not in data["ssh"][0]


def test_registry_example_yaml_validates(tmp_path):
    """config/registry.example.yaml must validate against the schema.
    If the example drifts out of sync with the schema, future users
    copying it will get schema errors — so lock the example here."""
    example = SKILL_ROOT / "config" / "registry.example.yaml"
    load_registry(example)  # raises RegistryError if invalid


def test_registry_accepts_publish_scp_sink(tmp_path):
    """publish: array with type=scp and required fields validates."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh: []\n"
        "github: []\n"
        "publish:\n"
        "  - type: scp\n"
        "    destination: pkgfence@control.example\n"
        "    key_file: ~/.ssh/pkgfence-publish\n"
        "    remote_base: /opt/pkgfence-reports\n"
        "    include: [md, sarif, jsonl]\n"
    )
    data = load_registry(reg)
    assert len(data["publish"]) == 1
    assert data["publish"][0]["type"] == "scp"
    assert data["publish"][0]["destination"] == "pkgfence@control.example"


def test_registry_publish_is_optional(tmp_path):
    """publish: is optional — registries without it must still validate."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\nroots: []\nprojects: []\nssh: []\ngithub: []\n"
    )
    data = load_registry(reg)
    assert "publish" not in data or data["publish"] == []


def test_registry_publish_rejects_unknown_sink_type(tmp_path):
    """publish entries with type other than 'scp' are rejected."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh: []\n"
        "github: []\n"
        "publish:\n"
        "  - type: rclone\n"  # Not yet supported
        "    destination: foo:bar\n"
    )
    with pytest.raises(RegistryError):
        load_registry(reg)


def test_ssh_entry_accepts_optional_port(tmp_path):
    """ssh items may optionally include a port (1-65535) for hosts that
    don't run sshd on the default port 22."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: mars\n"
        "    host: mars.example\n"
        "    user: scanuser\n"
        "    port: 2222\n"
        "    tier: 1\n"
        "github: []\n"
    )
    data = load_registry(reg)
    assert data["ssh"][0]["port"] == 2222


def test_ssh_entry_rejects_invalid_port(tmp_path):
    """port must be in 1-65535 range; out-of-range values are rejected."""
    reg = tmp_path / "registry.yaml"
    reg.write_text(
        "version: 1\n"
        "roots: []\n"
        "projects: []\n"
        "ssh:\n"
        "  - name: mars\n"
        "    host: mars.example\n"
        "    user: scanuser\n"
        "    port: 99999\n"
        "    tier: 1\n"
        "github: []\n"
    )
    with pytest.raises(RegistryError):
        load_registry(reg)

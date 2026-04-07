"""Tests for the `registry_cli add-ssh` subcommand (Phase 2)."""
from pathlib import Path

from scripts.registry_cli import main
from scripts.lib.registry import load_registry


def _init_registry(path: Path) -> None:
    path.write_text("version: 1\nroots: []\nprojects: []\nssh: []\ngithub: []\n")


def test_add_ssh_minimal(tmp_path):
    reg = tmp_path / "registry.yaml"
    _init_registry(reg)
    rc = main([
        "--registry", str(reg),
        "add-ssh",
        "--name", "dev-host-1",
        "--host", "192.0.2.10",
        "--user", "devuser",
        "--tier", "2",
    ])
    assert rc == 0
    data = load_registry(reg)
    assert len(data["ssh"]) == 1
    assert data["ssh"][0] == {
        "name": "dev-host-1",
        "host": "192.0.2.10",
        "user": "devuser",
        "tier": 2,
    }


def test_add_ssh_full(tmp_path):
    reg = tmp_path / "registry.yaml"
    _init_registry(reg)
    rc = main([
        "--registry", str(reg),
        "add-ssh",
        "--name", "mars",
        "--host", "mars.example",
        "--user", "scanuser",
        "--tier", "1",
        "--key-file", "~/.ssh/scan-key",
        "--scanner-user", "pkgfence-scan",
        "--use-sudo",
        "--discover-path", "/var/www",
        "--discover-path", "/var/www/vhosts",
    ])
    assert rc == 0
    data = load_registry(reg)
    entry = data["ssh"][0]
    assert entry["name"] == "mars"
    assert entry["host"] == "mars.example"
    assert entry["user"] == "scanuser"
    assert entry["tier"] == 1
    assert entry["key_file"] == "~/.ssh/scan-key"
    assert entry["scanner_user"] == "pkgfence-scan"
    assert entry["use_sudo"] is True
    assert entry["discover_paths"] == ["/var/www", "/var/www/vhosts"]


def test_add_ssh_duplicate_name_rejected(tmp_path):
    reg = tmp_path / "registry.yaml"
    _init_registry(reg)
    main(["--registry", str(reg), "add-ssh", "--name", "mars",
          "--host", "mars.example", "--user", "scanuser"])
    rc = main(["--registry", str(reg), "add-ssh", "--name", "mars",
               "--host", "other.example", "--user", "scanuser"])
    assert rc == 3

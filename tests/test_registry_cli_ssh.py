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
    assert data["ssh"][0] == {
        "name": "mars",
        "host": "mars.example",
        "user": "scanuser",
        "tier": 1,
        "key_file": "~/.ssh/scan-key",
        "scanner_user": "pkgfence-scan",
        "use_sudo": True,
        "discover_paths": ["/var/www", "/var/www/vhosts"],
    }


def test_add_ssh_duplicate_name_rejected(tmp_path):
    reg = tmp_path / "registry.yaml"
    _init_registry(reg)
    main(["--registry", str(reg), "add-ssh", "--name", "mars",
          "--host", "mars.example", "--user", "scanuser"])
    rc = main(["--registry", str(reg), "add-ssh", "--name", "mars",
               "--host", "other.example", "--user", "scanuser"])
    assert rc == 3


def test_remove_ssh_by_name(tmp_path):
    reg = tmp_path / "registry.yaml"
    _init_registry(reg)
    main(["--registry", str(reg), "add-ssh", "--name", "mars",
          "--host", "mars.example", "--user", "scanuser"])
    main(["--registry", str(reg), "add-ssh", "--name", "bespin",
          "--host", "bespin.example", "--user", "scanuser"])
    rc = main(["--registry", str(reg), "remove", "mars"])
    assert rc == 0
    data = load_registry(reg)
    assert [s["name"] for s in data["ssh"]] == ["bespin"]


def test_list_shows_ssh_targets(tmp_path, capsys):
    reg = tmp_path / "registry.yaml"
    _init_registry(reg)
    main(["--registry", str(reg), "add-ssh", "--name", "mars",
          "--host", "mars.example", "--user", "scanuser", "--tier", "1",
          "--discover-path", "/var/www"])
    capsys.readouterr()  # clear add-ssh output
    rc = main(["--registry", str(reg), "list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mars" in out
    assert "scanuser@mars.example" in out
    assert "(tier 1)" in out
    assert "discover_paths: /var/www" in out

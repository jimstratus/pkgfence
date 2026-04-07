"""pkgfence registry — CLI for managing the scan registry.

Subcommands:
    validate    Validate registry.yaml against the schema
    list        Print registered targets
    add-root    Add a local parent directory to scan (Task 3.5)
    add-project Add a specific project path (Task 3.6)
    remove      Remove a target by name or path (Task 3.6)

Exit codes:
    0 = success
    3 = configuration / registry error
"""
import argparse
import sys
from pathlib import Path

from scripts.lib.registry import load_registry, save_registry_atomic, RegistryError


def cmd_validate(args) -> int:
    try:
        load_registry(Path(args.registry))
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    print("OK: registry is valid")
    return 0


def cmd_list(args) -> int:
    try:
        reg = load_registry(Path(args.registry))
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    print(f"Registry version: {reg['version']}")
    print(f"\nRoots ({len(reg.get('roots', []))}):")
    for r in reg.get("roots", []):
        print(f"  - {r['path']} (tier {r.get('tier', 1)})")
    print(f"\nProjects ({len(reg.get('projects', []))}):")
    for p in reg.get("projects", []):
        print(f"  - {p['name']}: {p['path']}")
    print(f"\nSSH targets ({len(reg.get('ssh', []))}):")
    for s in reg.get("ssh", []):
        print(f"  - {s['name']}: {s['user']}@{s['host']}")
    print(f"\nGitHub accounts ({len(reg.get('github', []))}):")
    for g in reg.get("github", []):
        print(f"  - {g['account']}: orgs={g.get('orgs', [])}")
    return 0


def cmd_add_root(args) -> int:
    reg_path = Path(args.registry)
    try:
        reg = load_registry(reg_path) if reg_path.exists() else {
            "version": 1, "roots": [], "projects": [], "ssh": [], "github": [],
        }
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    new_root = {"path": args.path, "tier": args.tier}
    if args.exclude:
        new_root["exclude"] = args.exclude
    reg.setdefault("roots", []).append(new_root)
    try:
        save_registry_atomic(reg_path, reg)
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    print(f"Added root: {args.path} (tier {args.tier})")
    return 0


def cmd_add_project(args) -> int:
    reg_path = Path(args.registry)
    try:
        reg = load_registry(reg_path) if reg_path.exists() else {
            "version": 1, "roots": [], "projects": [], "ssh": [], "github": [],
        }
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3

    # Reject duplicate names
    existing = {p["name"] for p in reg.get("projects", [])}
    if args.name in existing:
        print(f"Error: project name {args.name!r} already exists", file=sys.stderr)
        return 3

    new_project = {"path": args.path, "name": args.name, "tier": args.tier}
    if args.note:
        new_project["note"] = args.note
    reg.setdefault("projects", []).append(new_project)
    try:
        save_registry_atomic(reg_path, reg)
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    print(f"Added project: {args.name} -> {args.path} (tier {args.tier})")
    return 0


def cmd_remove(args) -> int:
    """Remove a target by path (for roots) or name (for projects, ssh, github)."""
    reg_path = Path(args.registry)
    try:
        reg = load_registry(reg_path)
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3

    identifier = args.identifier
    removed = False

    # Match roots by path
    before = len(reg.get("roots", []))
    reg["roots"] = [r for r in reg.get("roots", []) if r.get("path") != identifier]
    if len(reg["roots"]) < before:
        removed = True

    # Match projects by name
    before = len(reg.get("projects", []))
    reg["projects"] = [p for p in reg.get("projects", []) if p.get("name") != identifier]
    if len(reg["projects"]) < before:
        removed = True

    # (Phase 2: match ssh and github by name)

    if not removed:
        print(f"Error: target {identifier!r} not found in registry", file=sys.stderr)
        return 3

    try:
        save_registry_atomic(reg_path, reg)
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3
    print(f"Removed: {identifier}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pkgfence registry")
    parser.add_argument(
        "--registry", default="state/registry.yaml",
        help="Path to registry.yaml (default: state/registry.yaml)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate", help="Validate registry against schema")
    sub.add_parser("list", help="Print registered targets")

    add_root = sub.add_parser("add-root", help="Add a local parent directory to scan")
    add_root.add_argument("path", help="Path to the parent directory")
    add_root.add_argument("--tier", type=int, default=1, choices=[1, 2, 3])
    add_root.add_argument("--exclude", action="append", default=None)

    add_project = sub.add_parser("add-project", help="Add a specific project path")
    add_project.add_argument("path", help="Absolute path to the project")
    add_project.add_argument("--name", required=True, help="Short name (must be unique)")
    add_project.add_argument("--tier", type=int, default=1, choices=[1, 2, 3])
    add_project.add_argument("--note", default=None, help="Optional note")

    remove_cmd = sub.add_parser("remove", help="Remove a target by path or name")
    remove_cmd.add_argument("identifier", help="Path (for roots) or name (for projects/ssh/github)")

    args = parser.parse_args(argv)
    if args.cmd == "validate":
        return cmd_validate(args)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "add-root":
        return cmd_add_root(args)
    if args.cmd == "add-project":
        return cmd_add_project(args)
    if args.cmd == "remove":
        return cmd_remove(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())

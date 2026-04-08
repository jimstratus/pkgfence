"""`pkgfence ssh precheck <name>` — verify an SSH target is ready to scan.

Checks:
1. Target exists in registry
2. Host reachable via SSH (BatchMode=yes; no password prompts)
3. osv-scanner present on the remote (prints version)
4. Each discover_path exists on the remote (via `ls`)

Exit codes:
    0 = all checks passed
    2 = host unreachable or scanner missing
    3 = target not in registry / config error
"""
import argparse
import sys
from pathlib import Path

from scripts.lib.registry import load_registry, RegistryError
from scripts.lib.ssh_runner import SSHRunner, SSHUnreachableError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pkgfence ssh precheck")
    parser.add_argument("--registry", default="state/registry.yaml",
                        help="Path to registry.yaml")
    parser.add_argument("name", help="SSH target name from registry")
    args = parser.parse_args(argv)

    try:
        reg = load_registry(Path(args.registry))
    except RegistryError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 3

    targets = [t for t in reg.get("ssh", []) if t.get("name") == args.name]
    if not targets:
        print(f"Error: ssh target {args.name!r} not found in registry", file=sys.stderr)
        return 3
    target = targets[0]

    print(f"Precheck for {args.name} ({target['user']}@{target['host']}):")
    runner = SSHRunner(
        host=target["host"],
        user=target["user"],
        key_file=target.get("key_file"),
        use_sudo=target.get("use_sudo", False),
    )

    # Check 1: osv-scanner present
    try:
        version_output = runner.run(["osv-scanner", "--version"])
    except SSHUnreachableError as e:
        print(f"  [FAIL] ssh unreachable: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"  [FAIL] {e}", file=sys.stderr)
        return 2
    print(f"  [OK] osv-scanner present: {version_output.strip()}")

    # Check 2: each discover_path exists
    for dpath in target.get("discover_paths") or []:
        try:
            runner.run(["ls", dpath])
        except SSHUnreachableError:
            print(f"  [FAIL] discover_path {dpath!r} unreachable", file=sys.stderr)
            return 2
        print(f"  [OK] discover_path exists: {dpath}")

    print(f"\nAll checks passed for {args.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

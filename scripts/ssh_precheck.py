"""`pkgfence ssh precheck <name>` — verify an SSH target is ready to scan.

Checks:
1. Target exists in registry
2. Host reachable via SSH (BatchMode=yes; no password prompts)
3. osv-scanner present on the remote (prints version)
4. Each discover_path exists on the remote (via `stat`)

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
    # osv-scanner is in the S3 allowlist, so ValueError cannot fire here.
    try:
        version_output = runner.run(["osv-scanner", "--version"])
    except SSHUnreachableError as e:
        print(f"  [FAIL] ssh unreachable: {e}", file=sys.stderr)
        return 2
    print(f"  [OK] osv-scanner present: {version_output.strip()}")

    # Check 2: each discover_path exists
    # We use `stat <path>` rather than `ls <path>` because SSHRunner.run()
    # only raises on rc=255 (SSH connect failure); a nonzero exit from ls
    # (path missing) would silently return empty stdout and appear as [OK].
    # stat on a missing path also returns empty stdout (stderr is discarded
    # by SSHRunner), so we inspect stdout directly: empty → path missing.
    # We iterate ALL paths before returning so the operator gets a complete
    # picture in one invocation.
    failed_paths: list[str] = []
    for dpath in target.get("discover_paths") or []:
        try:
            stat_output = runner.run(["stat", dpath])
        except SSHUnreachableError:
            print(f"  [FAIL] discover_path {dpath!r} unreachable", file=sys.stderr)
            failed_paths.append(dpath)
            continue
        if stat_output.strip():
            print(f"  [OK] discover_path exists: {dpath}")
        else:
            print(f"  [FAIL] discover_path missing: {dpath}", file=sys.stderr)
            failed_paths.append(dpath)

    if failed_paths:
        return 2

    print(f"\nAll checks passed for {args.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

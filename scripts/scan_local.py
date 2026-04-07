"""Local scanner orchestration — runs osv-scanner against discovered manifests
and normalizes results to Finding records.

Round 2 + Task 1.5 finding: osv-scanner v2.3.3 exit codes:
    0   = scan completed, no vulns (success)
    1   = scan completed, vulns found (SUCCESS, not error)
    2   = scanner error
    127 = binary not found
    128 = "No package sources found" — empty/malformed lockfile

Task 8.5 handles exit-128 / parse failures via SCAN_ERROR Finding records.
"""
import re
import subprocess
from typing import Optional


# Exit codes that mean osv-scanner ran successfully (whether or not vulns were found)
OSV_SUCCESS_EXIT_CODES = {0, 1}


def detect_scanner(name: str = "osv-scanner") -> Optional[str]:
    """Run `<name> --version` and parse the version string.

    Returns:
        Version string (e.g. '2.3.3') if installed, None if not found.
    """
    try:
        result = subprocess.run(
            [name, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    # Parse "osv-scanner version 2.3.3" or similar
    match = re.search(r"version\s+(\d+\.\d+\.\d+)", result.stdout)
    if match:
        return match.group(1)
    return None


class ScannerError(Exception):
    """osv-scanner failed for an unexpected reason (exit code other than
    0, 1, 127, or 128)."""


class EmptyLockfileError(ScannerError):
    """Special case: lockfile is empty or malformed.
    osv-scanner exit 128 with 'No package sources found' on stderr.
    Task 8.5 catches this and emits a SCAN_ERROR Finding."""


def run_osv_scanner_lockfile(lockfile_path: str) -> str:
    """Run `osv-scanner -L <lockfile_path> --format json` and return raw JSON.

    Exit code semantics (verified against osv-scanner v2.3.3):
        0   -> success, no vulns. JSON returned.
        1   -> success, vulns found. JSON returned.
        2   -> real scanner error. ScannerError raised.
        127 -> binary not found. ScannerError raised.
        128 -> empty/malformed lockfile. EmptyLockfileError raised.

    Returns:
        Raw JSON string from osv-scanner stdout.

    Raises:
        ScannerError: on exit 2 or 127 or unknown non-success exit
        EmptyLockfileError: on exit 128 (handle via Task 8.5)
    """
    try:
        result = subprocess.run(
            ["osv-scanner", "-L", lockfile_path, "--format", "json"],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except FileNotFoundError as e:
        raise ScannerError(f"osv-scanner binary not found: {e}") from e
    except subprocess.TimeoutExpired as e:
        raise ScannerError(f"osv-scanner timed out scanning {lockfile_path}") from e

    if result.returncode in OSV_SUCCESS_EXIT_CODES:
        return result.stdout
    if result.returncode == 128:
        raise EmptyLockfileError(
            f"osv-scanner: no package sources found in {lockfile_path} "
            f"(exit 128, stderr: {result.stderr.strip()})"
        )
    if result.returncode == 127:
        raise ScannerError(
            f"osv-scanner binary not found in PATH (exit 127)"
        )
    raise ScannerError(
        f"osv-scanner failed with exit {result.returncode} on {lockfile_path}: "
        f"{result.stderr.strip()[:500]}"
    )

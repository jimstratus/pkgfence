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

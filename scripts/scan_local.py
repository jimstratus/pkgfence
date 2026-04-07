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


import json as _json

from scripts.lib.purl import build_purl
from scripts.lib.types import Finding, new_finding


def _extract_severity(vuln_severity_list: list[dict]) -> str:
    """Extract a severity bucket from osv-scanner vulnerability severity list.

    osv-scanner emits severity as a list of dicts with 'type' and 'score'.
    Score may be a CVSS vector string or a numeric string. We map:
        score >= 9.0 -> critical
        score >= 7.0 -> high
        score >= 4.0 -> medium
        score >  0.0 -> low
        else            -> info
    """
    if not vuln_severity_list:
        return "medium"  # default if scanner didn't provide one
    for entry in vuln_severity_list:
        score_str = entry.get("score", "")
        # Try numeric extraction
        m = re.search(r"\b(\d+\.\d+|\d+)\b", score_str)
        if m:
            try:
                score = float(m.group(1))
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                if score > 0.0:
                    return "low"
                return "info"
            except ValueError:
                pass
    return "medium"


def parse_osv_output(raw_json: str, manifest_path: str, target: str) -> list[Finding]:
    """Parse osv-scanner JSON output into normalized Finding records.

    osv-scanner JSON shape:
        {"results": [
            {"source": {"path": "...", "type": "lockfile"},
             "packages": [
                 {"package": {"name": "...", "version": "...", "ecosystem": "..."},
                  "vulnerabilities": [
                      {"id": "GHSA-...", "summary": "...",
                       "severity": [{"type": "CVSS_V3", "score": "..."}],
                       "aliases": ["CVE-..."]}
                  ]}
             ]}
        ]}

    Returns a list of Finding TypedDicts (one per vuln per package).
    """
    try:
        data = _json.loads(raw_json)
    except _json.JSONDecodeError as e:
        raise ScannerError(f"osv-scanner returned invalid JSON: {e}") from e

    findings: list[Finding] = []
    for result in data.get("results", []):
        for pkg_entry in result.get("packages", []):
            pkg = pkg_entry.get("package", {})
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            ecosystem = pkg.get("ecosystem", "").lower()
            try:
                purl = build_purl(ecosystem, name, version)
            except Exception:
                # Unknown ecosystem — fall back to a synthetic purl
                purl = f"pkg:{ecosystem or 'unknown'}/{name}@{version}"

            for vuln in pkg_entry.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "UNKNOWN")
                severity = _extract_severity(vuln.get("severity", []))
                f = new_finding(
                    purl=purl,
                    vuln_id=vuln_id,
                    severity=severity,
                    manifest_path=manifest_path,
                    target=target,
                    description=vuln.get("summary", ""),
                    aliases=vuln.get("aliases", []),
                    scanner_source="osv-scanner",
                )
                findings.append(f)
    return findings

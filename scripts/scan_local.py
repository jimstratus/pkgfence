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


from scripts.lib.osv_client import OSVClient


def _parse_npm_lockfile_packages(lockfile_path: str) -> list[dict]:
    """Extract (name, version) tuples from npm package-lock.json.

    Returns list of {package: {name, ecosystem}, version} dicts ready
    for OSVClient.querybatch().
    """
    try:
        with open(lockfile_path, encoding="utf-8") as fh:
            data = _json.loads(fh.read())
    except (OSError, _json.JSONDecodeError) as e:
        raise ScannerError(f"Failed to parse npm lockfile {lockfile_path}: {e}") from e

    queries = []
    packages = data.get("packages", {})
    for pkg_path, pkg_data in packages.items():
        if pkg_path == "":
            continue  # root package
        # node_modules/<scope>/<name> or node_modules/<name>
        parts = pkg_path.split("node_modules/", 1)
        if len(parts) != 2:
            continue
        name = parts[1]
        version = pkg_data.get("version")
        if not version:
            continue
        queries.append({
            "package": {"name": name, "ecosystem": "npm"},
            "version": version,
        })
    return queries


def scan_manifest(manifest: dict) -> list[Finding]:
    """Scan a single manifest. Prefers osv-scanner if installed; falls back
    to direct OSV API query if not.

    Args:
        manifest: dict with keys 'path', 'ecosystem', 'target', 'manifest_hash'

    Returns:
        list[Finding]
    """
    manifest_path = manifest["path"]
    target = manifest.get("target", "")
    ecosystem = manifest.get("ecosystem", "").lower()

    if detect_scanner("osv-scanner") is not None:
        # Preferred path: use osv-scanner subprocess
        try:
            raw = run_osv_scanner_lockfile(manifest_path)
            return parse_osv_output(raw, manifest_path=manifest_path, target=target)
        except EmptyLockfileError:
            # Task 8.5 handles this case in scan_manifest_safely
            raise
        except ScannerError:
            raise

    # Fallback: parse manifest locally and query OSV API directly
    if ecosystem != "npm":
        # MVP fallback only handles npm. Other ecosystems get a SCAN_ERROR
        # in Task 8.5's scan_manifest_safely.
        raise ScannerError(
            f"osv-scanner not installed and ecosystem {ecosystem!r} fallback "
            "not implemented in MVP (only npm has a fallback path)"
        )

    queries = _parse_npm_lockfile_packages(manifest_path)
    if not queries:
        return []

    client = OSVClient()
    results = client.querybatch(queries)

    findings: list[Finding] = []
    for query, result in zip(queries, results):
        pkg_name = query["package"]["name"]
        pkg_version = query["version"]
        try:
            purl = build_purl("npm", pkg_name, pkg_version)
        except Exception:
            purl = f"pkg:npm/{pkg_name}@{pkg_version}"
        for vuln in result.get("vulns", []):
            findings.append(new_finding(
                purl=purl,
                vuln_id=vuln.get("id", "UNKNOWN"),
                severity=_extract_severity(vuln.get("severity", [])),
                manifest_path=manifest_path,
                target=target,
                description=vuln.get("summary", ""),
                aliases=vuln.get("aliases", []),
                scanner_source="osv-api",
            ))
    return findings


def scan_manifest_safely(manifest: dict) -> list[Finding]:
    """Wrapper around scan_manifest that catches ScannerError /
    EmptyLockfileError and returns a SCAN_ERROR Finding instead of
    propagating the exception.

    M3 critic gap fix: a single bad target must not block the entire scan.
    The orchestrator continues with other targets and the bad one shows
    up as a SCAN_ERROR record in the report.
    """
    try:
        return scan_manifest(manifest)
    except (ScannerError, EmptyLockfileError, OSError) as e:
        # Emit a SCAN_ERROR Finding so the report shows what failed
        return [new_finding(
            purl=f"pkg:scan-error/{manifest.get('target', 'unknown')}@-",
            vuln_id="SCAN_ERROR",
            severity="info",
            manifest_path=manifest.get("path", ""),
            target=manifest.get("target", ""),
            status="SCAN_ERROR",
            description=str(e),
        )]


def scan_all_manifests(manifests: list[dict]) -> list[Finding]:
    """Scan a list of manifests. Per-manifest failures are isolated via
    scan_manifest_safely so one bad lockfile doesn't block the rest.
    """
    all_findings: list[Finding] = []
    for manifest in manifests:
        all_findings.extend(scan_manifest_safely(manifest))
    return all_findings

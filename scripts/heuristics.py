"""Behavioral heuristics for supply-chain malware detection.

Four independent checks: entropy (typosquatting), age (new/abandoned),
lifecycle scripts (install-time code execution), provenance (SLSA attestation).

Heuristics run from lockfile data already present on the scanner host.
No external API calls. Remote SSH targets skip lifecycle + provenance
to preserve S4 (no remote file content exfiltration).
"""
import datetime
import math
import re
from scripts.lib.types import Finding, is_status_record


def shannon_entropy(s: str) -> float:  # pragma: no cover — content covered
    if not s:
        return 0.0
    n = len(s)
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _extract_name_from_purl(purl: str) -> str:
    if not purl or not purl.startswith("pkg:"):
        return ""
    rest = purl[4:]
    try:
        _, remainder = rest.split("/", 1)
    except ValueError:
        return ""
    if "@" in remainder:
        return remainder.rsplit("@", 1)[0]
    return remainder


def _manifest_key_from_purl(purl: str) -> str:
    """pkg:npm/lodash@4.17.10 -> npm:lodash"""
    if not purl.startswith("pkg:"):
        return ""
    rest = purl[4:]
    try:
        eco, remainder = rest.split("/", 1)
    except ValueError:
        return ""
    name = remainder.rsplit("@", 1)[0] if "@" in remainder else remainder
    return f"{eco}:{name}"


def _parse_iso(ts: str) -> datetime.datetime | None:
    try:
        dt = datetime.datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _check_entropy(findings: list[Finding], config: dict) -> None:
    threshold = (config.get("entropy") or {}).get("threshold", 7.0)
    for f in findings:
        if is_status_record(f):
            continue
        purl = f.get("purl", "")
        name = _extract_name_from_purl(purl)
        if not name:
            continue
        score = shannon_entropy(name)
        f["entropy_score"] = score
        if score > threshold:
            flags = list(f.get("heuristic_flags", []))
            flags.append(f"entropy:{score:.1f}")
            f["heuristic_flags"] = flags


def _check_age(
    findings: list[Finding], manifest_data: dict, config: dict
) -> None:
    new_package_days = (config.get("age") or {}).get("new_package_days", 30)
    abandoned_days = (config.get("age") or {}).get("abandoned_days", 365)
    now = datetime.datetime.now(datetime.timezone.utc)
    for f in findings:
        if is_status_record(f):
            continue
        md = manifest_data.get(f.get("manifest_path", ""), {})
        if not md:
            continue
        pkg_key = _manifest_key_from_purl(f.get("purl", ""))
        pkg_data = md.get(pkg_key, {})
        if not pkg_data:
            continue
        flags = list(f.get("heuristic_flags", []))
        created = pkg_data.get("created")
        if created:
            created_dt = _parse_iso(created)
            if created_dt and (now - created_dt).days < new_package_days:
                flags.append("age:new-package")
        modified = pkg_data.get("modified")
        if modified:
            modified_dt = _parse_iso(modified)
            if modified_dt and (now - modified_dt).days > abandoned_days:
                flags.append("age:abandoned")
        if flags != (f.get("heuristic_flags") or []):
            f["heuristic_flags"] = flags


_NETWORK_OPS_RE = re.compile(
    r"\b(curl|wget|fetch|http\.get|http\.request|node\s+-e|\beval\b)",
    re.IGNORECASE,
)

_LIFECYCLE_SCRIPTS = frozenset({"preinstall", "postinstall", "prepare"})


def _check_lifecycle_scripts(
    findings: list[Finding], manifest_data: dict, config: dict
) -> None:
    escalate = config.get("lifecycle_script_escalate_if_network_op", "critical")
    for f in findings:
        if is_status_record(f):
            continue
        if f.get("target", "") != "local":
            continue
        md = manifest_data.get(f.get("manifest_path", ""), {})
        if not md:
            continue
        pkg_key = _manifest_key_from_purl(f.get("purl", ""))
        pkg_data = md.get(pkg_key, {})
        scripts = pkg_data.get("scripts", {})
        if not scripts:
            continue
        flags = list(f.get("heuristic_flags", []))
        for script_name in _LIFECYCLE_SCRIPTS:
            script_body = (scripts.get(script_name) or "").strip()
            if script_body:
                flags.append(f"lifecycle:{script_name}")
                f["lifecycle_script"] = f"{script_name}:{script_body[:120]}"
                if _NETWORK_OPS_RE.search(script_body):
                    flags.append("lifecycle:network-op")
                    if escalate and f.get("severity", "") != "critical":
                        f["original_severity"] = f.get("severity")
                        f["severity"] = "critical"
        if flags:
            f["heuristic_flags"] = flags


def _check_provenance(
    findings: list[Finding], manifest_data: dict, config: dict
) -> None:
    for f in findings:
        if is_status_record(f):
            continue
        if f.get("target", "") != "local":
            continue
        md = manifest_data.get(f.get("manifest_path", ""), {})
        if not md:
            continue
        pkg_key = _manifest_key_from_purl(f.get("purl", ""))
        pkg_data = md.get(pkg_key, {})
        if pkg_data.get("provenance") is not True:
            f["missing_provenance"] = True
            severity_missing = config.get("provenance_expected_missing")
            if severity_missing and f.get("severity", "medium") not in (
                "critical", "info"
            ):
                f["original_severity"] = f.get("severity")
                f["severity"] = severity_missing


def run_heuristics(
    findings: list[Finding], manifest_data: dict, config: dict
) -> list[Finding]:
    """Run all behavioral heuristics. Remote targets skip lifecycle + provenance."""
    if not config or not findings:
        return findings
    _check_entropy(findings, config)
    _check_age(findings, manifest_data, config)
    _check_lifecycle_scripts(findings, manifest_data, config)
    _check_provenance(findings, manifest_data, config)
    return findings

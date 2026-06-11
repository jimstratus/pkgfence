"""Post-scan publish — pushes report artifacts to configured sinks.

Best-effort by design: failures are logged and added to degraded_modes
in the NEXT scan's report (since the current scan's report is already
written by the time publish runs). Exit code is NEVER changed by
publish status — the local report is the source of truth.

Currently supports:
    type: scp — scp the artifacts to a remote host:path

Planned (not in v0.2.0):
    type: rclone — rclone copy with arbitrary backends
    type: git    — commit + push to a private repo
"""
import re
import shlex
import socket
import subprocess
from pathlib import Path
from typing import Any

from scripts.lib.logger import get_logger
from scripts.lib.proc import run_capture

log = get_logger(__name__)


# Map artifact key -> file extension
ARTIFACT_EXTENSIONS = {
    "md": ".md",
    "sarif": ".sarif",
    "jsonl": ".jsonl",
}


class PublishError(Exception):
    """Raised when a publish operation fails. Caller catches and logs;
    publish failures NEVER bubble up to change the scan exit code."""


def _scanner_hostname() -> str:
    """Return a stable, path-safe hostname for the scanner machine.
    Used as the subdirectory under remote_base so multi-source publishes
    don't collide.

    Sanitizes the value from socket.gethostname():
    - Replaces any character outside [A-Za-z0-9._-] with '_' so the
      result is safe to embed in a remote path component.
    - Falls back to 'unknown-host' if the hostname is empty.

    Defense-in-depth: hostnames SHOULD be RFC-1123 compliant, but
    socket.gethostname() returns whatever the OS reports, and we send
    this string into a remote command. Sanitizing here keeps publish
    safe regardless of what the underlying OS exposes.
    """
    raw = socket.gethostname() or ""
    # Keep only path-safe chars; collapse anything else to underscore
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", raw)
    return sanitized or "unknown-host"


def _resolve_artifacts(
    state_dir: Path,
    run_id: str,
    include: list[str],
) -> list[Path]:
    """Resolve which local artifact files exist for this run + include set.

    The .md and .sarif files live in state_dir/reports/<run_id>.<ext>.
    The .jsonl audit log lives in state_dir/audit.jsonl.d/<run_id>.jsonl.
    Skip files that don't exist (e.g., a config error scan may not produce
    a sarif).
    """
    paths: list[Path] = []
    for kind in include:
        ext = ARTIFACT_EXTENSIONS.get(kind)
        if ext is None:
            log.warning("publish: unknown artifact kind %r, skipping", kind)
            continue
        if kind == "jsonl":
            path = state_dir / "audit.jsonl.d" / f"{run_id}.jsonl"
        else:
            path = state_dir / "reports" / f"{run_id}{ext}"
        if path.exists():
            paths.append(path)
        else:
            log.warning("publish: artifact missing, skipping: %s", path)
    return paths


def _build_scp_command(
    local_path: Path,
    sink: dict[str, Any],
    scanner_host: str,
) -> list[str]:
    """Build the scp argv to push one artifact to one sink.

    The remote path is <remote_base>/<scanner_host>/<filename>. The
    scanner_host subdirectory keeps multi-scanner publishes isolated.

    Required scp options:
        -i <key_file>          : the dedicated publish key (if configured)
        -o IdentitiesOnly=yes  : ONLY use the -i key, ignore ssh-agent
        -o BatchMode=yes       : never prompt; fail fast
        -o StrictHostKeyChecking=accept-new  : auto-accept first connection

    Without IdentitiesOnly=yes, ssh-agent fans out other keys first and
    hits the server's MaxAuthTries (default 6) before reaching the specified
    -i key, causing 'Too many authentication failures' disconnects. This
    is the gotcha that surfaced during dogfood setup.
    """
    destination = sink["destination"]
    remote_base = sink.get("remote_base", "/opt/pkgfence-reports")
    remote_path = f"{destination}:{remote_base}/{scanner_host}/{local_path.name}"

    cmd = ["scp"]
    if sink.get("key_file"):
        cmd += ["-i", str(Path(sink["key_file"]).expanduser())]
    cmd += [
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        str(local_path),
        remote_path,
    ]
    return cmd


def _ensure_remote_dir(
    sink: dict[str, Any],
    scanner_host: str,
) -> None:
    """ssh into the destination once before scp to mkdir -p the
    scanner_host subdirectory. Necessary because scp does not create
    intermediate directories on its own.

    Same SSH options as the scp call (IdentitiesOnly=yes + BatchMode=yes).
    The remote_dir path is shell-quoted via shlex.quote() before being
    sent to the remote shell, so any unexpected character in scanner_host
    or remote_base cannot break out of the path argument.

    Raises PublishError on failure.
    """
    destination = sink["destination"]  # user@host
    remote_base = sink.get("remote_base", "/opt/pkgfence-reports")
    remote_dir = f"{remote_base}/{scanner_host}"

    # Shell-quote the remote path so any metacharacters are literal.
    # ssh joins extra args with spaces and sends a single command string
    # to the remote shell, so list-form here does NOT escape shell parsing.
    quoted_remote_dir = shlex.quote(remote_dir)

    cmd = ["ssh"]
    if sink.get("key_file"):
        cmd += ["-i", str(Path(sink["key_file"]).expanduser())]
    cmd += [
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        destination,
        f"mkdir -p {quoted_remote_dir}",
    ]
    try:
        result = run_capture(cmd, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        raise PublishError(f"mkdir-p failed: {e}") from e
    if result.returncode != 0:
        raise PublishError(
            f"mkdir -p {remote_dir} failed (rc={result.returncode}): "
            f"{result.stderr.strip()}"
        )


def publish_run(
    sinks: list[dict[str, Any]],
    state_dir: Path,
    run_id: str,
) -> list[str]:
    """Publish the scan's artifacts to all configured sinks.

    Returns a list of degraded-mode strings (one per failed sink) that
    the caller should add to the NEXT scan's degraded_modes list (the
    current scan's report is already written by the time we run).

    NEVER raises. NEVER changes the scan exit code. Best-effort by design.
    """
    if not sinks:
        return []

    failures: list[str] = []
    scanner_host = _scanner_hostname()

    for sink in sinks:
        sink_type = sink.get("type")
        destination = sink.get("destination", "<unknown>")
        if sink_type != "scp":
            log.warning("publish: unknown sink type %r, skipping", sink_type)
            failures.append(f"publish: unsupported sink type {sink_type!r}")
            continue

        include = list(sink.get("include") or ["md", "sarif", "jsonl"])
        artifacts = _resolve_artifacts(state_dir, run_id, include)
        if not artifacts:
            log.warning("publish: no artifacts to push for run %s", run_id)
            failures.append(f"publish: no artifacts for run {run_id}")
            continue

        # Ensure the per-scanner_host subdirectory exists on the remote
        try:
            _ensure_remote_dir(sink, scanner_host)
        except PublishError as e:
            log.warning("publish: %s -> %s: %s", run_id, destination, e)
            failures.append(f"publish: FAIL {destination}: {e}")
            continue

        # Push each artifact
        for artifact in artifacts:
            cmd = _build_scp_command(artifact, sink, scanner_host)
            try:
                result = run_capture(cmd, timeout=120)
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                log.warning("publish: scp %s -> %s failed: %s",
                            artifact.name, destination, e)
                failures.append(f"publish: FAIL {destination} ({artifact.name}): {e}")
                continue
            if result.returncode != 0:
                log.warning(
                    "publish: scp %s -> %s rc=%d: %s",
                    artifact.name, destination, result.returncode,
                    result.stderr.strip(),
                )
                failures.append(
                    f"publish: FAIL {destination} ({artifact.name}): "
                    f"rc={result.returncode}"
                )
                continue
            log.info("publish: pushed %s -> %s:%s/%s/%s",
                     artifact.name, destination,
                     sink.get("remote_base", "/opt/pkgfence-reports"),
                     scanner_host, artifact.name)

    return failures

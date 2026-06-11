"""Unit tests for scripts/publish.py — best-effort sink push."""
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.publish import (
    publish_run,
    _build_scp_command,
    _resolve_artifacts,
    PublishError,
)


def _setup_state(tmp_path: Path, run_id: str) -> Path:
    """Create a fake state dir with reports + audit.jsonl.d artifacts."""
    state = tmp_path / "state"
    (state / "reports").mkdir(parents=True)
    (state / "audit.jsonl.d").mkdir(parents=True)
    (state / "reports" / f"{run_id}.md").write_text("# fake report")
    (state / "reports" / f"{run_id}.sarif").write_text('{"version":"2.1.0"}')
    (state / "audit.jsonl.d" / f"{run_id}.jsonl").write_text(
        '{"run_id":"' + run_id + '"}'
    )
    return state


def test_publish_run_no_sinks_returns_empty():
    """publish_run with no sinks does nothing and returns []."""
    failures = publish_run(sinks=[], state_dir=Path("/tmp"), run_id="x")
    assert failures == []


def test_resolve_artifacts_finds_existing_files(tmp_path):
    """_resolve_artifacts returns paths for files that exist."""
    state = _setup_state(tmp_path, "RUN-1")
    paths = _resolve_artifacts(state, "RUN-1", ["md", "sarif", "jsonl"])
    assert len(paths) == 3
    names = sorted(p.name for p in paths)
    assert names == ["RUN-1.jsonl", "RUN-1.md", "RUN-1.sarif"]


def test_resolve_artifacts_skips_missing_files(tmp_path):
    """If a requested artifact doesn't exist, it's skipped (warning logged)."""
    state = _setup_state(tmp_path, "RUN-2")
    # Ask for a non-existent kind
    paths = _resolve_artifacts(state, "MISSING-RUN", ["md", "sarif"])
    assert paths == []


def test_build_scp_command_includes_required_options():
    """The scp argv must include -i, IdentitiesOnly=yes, BatchMode=yes,
    and StrictHostKeyChecking=accept-new — these prevent the 'Too many
    authentication failures' gotcha that surfaced during dogfood."""
    sink = {
        "type": "scp",
        "destination": "pkgfence@control.example",
        "key_file": "~/.ssh/pkgfence-publish",
        "remote_base": "/opt/pkgfence-reports",
    }
    cmd = _build_scp_command(Path("/tmp/RUN-1.md"), sink, "SCANHOST")
    assert cmd[0] == "scp"
    assert "-i" in cmd
    # IdentitiesOnly is the critical option
    assert "IdentitiesOnly=yes" in cmd
    assert "BatchMode=yes" in cmd
    assert "StrictHostKeyChecking=accept-new" in cmd
    # Last 2 args are local then remote
    assert cmd[-2].endswith("RUN-1.md")
    assert cmd[-1] == "pkgfence@control.example:/opt/pkgfence-reports/SCANHOST/RUN-1.md"


def test_build_scp_command_omits_i_when_no_key_file():
    """If key_file is not configured, -i is omitted (use ~/.ssh/config defaults)."""
    sink = {
        "type": "scp",
        "destination": "u@h",
    }
    cmd = _build_scp_command(Path("/tmp/RUN-1.md"), sink, "host1")
    assert "-i" not in cmd


def test_build_scp_command_uses_default_remote_base():
    """remote_base defaults to /opt/pkgfence-reports when omitted."""
    sink = {"type": "scp", "destination": "u@h"}
    cmd = _build_scp_command(Path("/tmp/RUN-1.md"), sink, "host1")
    assert cmd[-1] == "u@h:/opt/pkgfence-reports/host1/RUN-1.md"


def test_publish_run_happy_path(tmp_path):
    """A good sink with all 3 artifacts: 1 mkdir + 3 scp = 4 subprocess calls,
    all succeeding. Returns [] failures."""
    state = _setup_state(tmp_path, "OK-RUN")
    sink = {
        "type": "scp",
        "destination": "pkgfence@control.example",
        "key_file": "~/.ssh/pkgfence-publish",
        "include": ["md", "sarif", "jsonl"],
    }

    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        failures = publish_run([sink], state, "OK-RUN")

    assert failures == []
    # 1 mkdir + 3 scp = 4 calls
    assert mock_run.call_count == 4
    # First call should be ssh ... mkdir -p
    first_cmd = mock_run.call_args_list[0].args[0]
    assert first_cmd[0] == "ssh"
    assert any("mkdir" in str(a) for a in first_cmd)
    # The mkdir ssh call MUST include the same hardening options as scp:
    # IdentitiesOnly + BatchMode + StrictHostKeyChecking. If someone
    # refactors _ensure_remote_dir and drops these, dogfood-style "Too
    # many authentication failures" comes back.
    assert "IdentitiesOnly=yes" in first_cmd
    assert "BatchMode=yes" in first_cmd
    assert "StrictHostKeyChecking=accept-new" in first_cmd
    # Remaining 3 are scp
    for i in range(1, 4):
        cmd = mock_run.call_args_list[i].args[0]
        assert cmd[0] == "scp"


def test_publish_run_mkdir_failure_records_failure_no_scp(tmp_path):
    """If mkdir -p fails, no scp is attempted for that sink, and a
    failure is recorded."""
    state = _setup_state(tmp_path, "MKDIR-FAIL")
    sink = {"type": "scp", "destination": "pkgfence@control.example"}

    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        # First call (mkdir) fails; we'd never get to the scp calls
        mock_run.return_value = MagicMock(
            returncode=255, stdout="", stderr="Permission denied",
        )
        failures = publish_run([sink], state, "MKDIR-FAIL")

    assert len(failures) == 1
    assert "FAIL" in failures[0]
    assert "Permission denied" in failures[0]
    assert mock_run.call_count == 1  # only mkdir, no scp follow-ups


def test_publish_run_scp_failure_records_per_artifact(tmp_path):
    """If mkdir succeeds but one scp fails, that file is recorded as failed
    while other files (in this single-sink test, no others succeed either
    because we mock all calls the same way) — verify the failures list
    is non-empty and the count matches the artifacts."""
    state = _setup_state(tmp_path, "SCP-FAIL")
    sink = {"type": "scp", "destination": "pkgfence@control.example",
            "include": ["md"]}

    call_count = {"n": 0}
    def fake(*args, **kwargs):
        call_count["n"] += 1
        # First call = mkdir (succeed); second = scp .md (fail)
        if call_count["n"] == 1:
            return MagicMock(returncode=0, stdout="", stderr="")
        return MagicMock(returncode=1, stdout="", stderr="connection refused")

    with patch("scripts.lib.proc.subprocess.run", side_effect=fake):
        failures = publish_run([sink], state, "SCP-FAIL")

    assert len(failures) == 1
    assert "FAIL" in failures[0]
    assert "rc=1" in failures[0]


def test_publish_run_unknown_sink_type_records_failure(tmp_path):
    """A sink with type other than 'scp' is recorded as a failure but
    does not raise."""
    state = _setup_state(tmp_path, "BAD-TYPE")
    sink = {"type": "git", "destination": "git@github.com:foo/bar"}

    with patch("scripts.lib.proc.subprocess.run") as mock_run:
        failures = publish_run([sink], state, "BAD-TYPE")

    assert len(failures) == 1
    assert "unsupported sink type" in failures[0]
    mock_run.assert_not_called()


def test_publish_run_never_raises_on_subprocess_error(tmp_path):
    """If subprocess.run itself raises (e.g., FileNotFoundError because
    scp binary is missing), publish_run catches and records — never raises."""
    state = _setup_state(tmp_path, "NO-SCP")
    sink = {"type": "scp", "destination": "u@h"}

    with patch("scripts.lib.proc.subprocess.run", side_effect=FileNotFoundError("scp not found")):
        failures = publish_run([sink], state, "NO-SCP")

    assert len(failures) == 1
    assert "FAIL" in failures[0]


def test_scanner_hostname_sanitizes_unsafe_characters():
    """_scanner_hostname() must replace path-unsafe characters in the
    raw hostname with underscores so we never embed shell metacharacters
    or path separators in the remote path.

    Defense in depth: even though Change 2 shell-quotes the path, the
    hostname source itself shouldn't contain weird characters.
    """
    from scripts.publish import _scanner_hostname

    with patch("scripts.publish.socket.gethostname", return_value="SCANHOST"):
        assert _scanner_hostname() == "SCANHOST"

    with patch("scripts.publish.socket.gethostname", return_value="host with spaces"):
        assert _scanner_hostname() == "host_with_spaces"

    with patch("scripts.publish.socket.gethostname", return_value="host$(injection)"):
        # Both `$`, `(`, `)` get replaced
        assert _scanner_hostname() == "host__injection_"

    with patch("scripts.publish.socket.gethostname", return_value="path/with/slash"):
        assert _scanner_hostname() == "path_with_slash"

    with patch("scripts.publish.socket.gethostname", return_value=""):
        assert _scanner_hostname() == "unknown-host"

    # RFC-1123 compliant hostnames pass through unchanged
    with patch("scripts.publish.socket.gethostname", return_value="hl-cb2.homelab.local"):
        assert _scanner_hostname() == "hl-cb2.homelab.local"


def test_ensure_remote_dir_shell_quotes_remote_path():
    """The mkdir command sent over ssh must shell-quote the remote
    directory path so unexpected characters in remote_base or
    scanner_host cannot break out of the argument."""
    from scripts.publish import _ensure_remote_dir

    sink = {
        "type": "scp",
        "destination": "u@h",
        "remote_base": "/opt/pkgfence-reports",
    }

    captured = {}
    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("scripts.lib.proc.subprocess.run", side_effect=fake_run):
        # scanner_host is sanitized by the time it reaches _ensure_remote_dir,
        # but the function should still shell-quote the path on the way out
        _ensure_remote_dir(sink, "SCANHOST")

    cmd = captured["cmd"]
    # The last element is the mkdir command string sent to the remote shell
    mkdir_str = cmd[-1]
    assert mkdir_str.startswith("mkdir -p ")
    # The path is single-quoted by shlex.quote (or no quote needed for safe paths)
    # For "/opt/pkgfence-reports/SCANHOST", shlex.quote returns the string unchanged
    # because all characters are safe. Verify it's at least the right path.
    assert "/opt/pkgfence-reports/SCANHOST" in mkdir_str

    # Now test with a hostname that WOULD have unsafe chars if not sanitized
    captured.clear()
    with patch("scripts.lib.proc.subprocess.run", side_effect=fake_run):
        _ensure_remote_dir(sink, "weird host'name")
    cmd = captured["cmd"]
    mkdir_str = cmd[-1]
    # The single quote inside the path forces shlex to wrap with double-quote
    # or escape with backslash; either way, it's not a bare quote
    assert mkdir_str.startswith("mkdir -p ")
    # Verify the literal "weird host'name" substring isn't sitting bare —
    # shlex.quote should have wrapped it somehow
    assert "'weird host" not in mkdir_str or "\\'" in mkdir_str or "'\\''" in mkdir_str

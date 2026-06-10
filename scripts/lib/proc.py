"""Single subprocess wrapper for pkgfence.

Every subprocess.run MUST set encoding="utf-8", errors="replace": Windows
defaults to cp1252 and crashes on non-ASCII scanner output (documented
gotcha). This helper is the one place that knows that (issue #18)."""
import subprocess


def run_capture(argv: list[str], timeout: int) -> "subprocess.CompletedProcess[str]":
    """Run argv capturing text output with the Windows-safe encoding flags.
    Never raises on nonzero exit (check=False); propagates TimeoutExpired,
    FileNotFoundError, OSError for callers to translate."""
    return subprocess.run(
        argv, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
        timeout=timeout, check=False,
    )

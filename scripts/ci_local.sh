#!/usr/bin/env bash
# Local stand-in for .github/workflows/test.yml when the authenticated
# token lacks the `workflow` scope (cannot push workflow file changes).
#
# Mirrors the intended CI steps:
#   1. full pytest suite
#   2. safety invariants S1–S4 as a dedicated verification step
#
# Usage (from repo root, with .[dev] installed):
#   bash scripts/ci_local.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -z "${PYTHON:-}" ]] || ! command -v "$PYTHON" >/dev/null 2>&1; then
  # Prefer project venv: Unix .venv/bin/python, then Windows .venv/Scripts/python.exe
  # (Git Bash / documented Windows setup), before falling back to globals.
  if [[ -x .venv/bin/python ]]; then
    PYTHON=.venv/bin/python
  elif [[ -x .venv/Scripts/python.exe ]]; then
    PYTHON=.venv/Scripts/python.exe
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
  elif command -v python >/dev/null 2>&1; then
    PYTHON=python
  else
    echo "error: no Python interpreter found (set PYTHON=...)" >&2
    exit 1
  fi
fi

echo "==> Full pytest suite ($PYTHON)"
"$PYTHON" -m pytest -v --tb=short

echo "==> Safety invariants S1–S4"
"$PYTHON" -m pytest tests/test_safety_invariants.py tests/test_s4_no_remote_content_exfil.py -v

echo "==> ci_local.sh OK"

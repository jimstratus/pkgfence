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

PYTHON="${PYTHON:-python}"
echo "==> Full pytest suite ($PYTHON)"
$PYTHON -m pytest -v --tb=short

echo "==> Safety invariants S1–S4"
$PYTHON -m pytest tests/test_safety_invariants.py tests/test_s4_no_remote_content_exfil.py -v

echo "==> ci_local.sh OK"

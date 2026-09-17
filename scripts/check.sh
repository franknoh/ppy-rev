#!/usr/bin/env bash
# Full local quality gate. Runs the same checks as CI.
set -euo pipefail
cd "$(dirname "$0")/.."

uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest "$@"

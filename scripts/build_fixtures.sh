#!/usr/bin/env bash
# Build every C fixture with each available compiler and optimization level.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHONPATH=tests uv run python -m fixtures.compile "$@"

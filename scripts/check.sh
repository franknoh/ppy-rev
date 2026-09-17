#!/usr/bin/env bash
# Full local quality gate. Runs the same checks as CI.
# With PPY_REV_REQUIRE_TOOLS=1, missing Ghidra or compilers fail instead of skipping.
set -euo pipefail
cd "$(dirname "$0")/.."

uv run ruff format --check .
uv run ruff check .
uv run pyright

if [[ -n "${PPY_REV_GHIDRA_HOME:-}" ]]; then
    (cd ghidra && ./gradlew --no-daemon --quiet --console=plain build)
elif [[ "${PPY_REV_REQUIRE_TOOLS:-}" == "1" ]]; then
    echo "PPY_REV_GHIDRA_HOME is required for the Java bridge checks" >&2
    exit 1
fi

uv run pytest "$@"

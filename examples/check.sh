#!/usr/bin/env bash
# Solve every example with the command its README documents and compare with the answer
# the README states. Run examples/fetch.sh first.
#
#     examples/check.sh            # all of them
#     examples/check.sh lactf      # only examples whose name contains "lactf"
set -uo pipefail
cd "$(dirname "$0")/.."
filter=${1:-}
failures=0

for readme in examples/*/README.md; do
    name=$(basename "$(dirname "$readme")")
    [[ -n $filter && $name != *$filter* ]] && continue
    command=$(sed -n 's/^uv run ppy-rev solve //p' "$readme" | head -1)
    answer=$(sed -n 's/^| Answer | `\(.*\)` |$/\1/p' "$readme" | head -1)
    [[ -z $command || -z $answer ]] && { echo "skip  $name (no command or answer)"; continue; }
    binary=${command%% *}
    if [[ ! -f $binary ]]; then
        echo "skip  $name (run examples/fetch.sh)"
        continue
    fi
    started=$(date +%s)
    output=$(eval "uv run ppy-rev solve $command" 2>&1)
    seconds=$(($(date +%s) - started))
    if grep -qF -- "$answer" <<<"$output"; then
        printf 'ok    %-28s %3ds\n' "$name" "$seconds"
    else
        printf 'FAIL  %-28s %3ds  %s\n' "$name" "$seconds" "$(grep -A1 '^Solution' <<<"$output" | tail -1)"
        failures=$((failures + 1))
    fi
done

echo "$failures failing"
[[ $failures -eq 0 ]]

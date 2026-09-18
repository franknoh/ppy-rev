#!/usr/bin/env bash
# Solve every example with the command its README documents and compare with the answer
# the README states. Run examples/fetch.sh first.
#
#     examples/check.sh            # all of them
#     examples/check.sh lactf      # only examples whose name contains "lactf"
#     VERIFY=1 examples/check.sh   # also run each answer on the real binary, in a container
set -uo pipefail
cd "$(dirname "$0")/.."
filter=${1:-}
verify=${VERIFY:+--verify}
failures=0

for readme in examples/*/README.md; do
    name=$(basename "$(dirname "$readme")")
    [[ -n $filter && $name != *$filter* ]] && continue
    command=$(sed -n 's/^uv run ppy-rev solve //p' "$readme" | head -1)
    answer=$(sed -n 's/^| Answer | `\(.*\)` |$/\1/p' "$readme" | head -1)
    # A README may state that the original binary rejects every input on this machine.
    expected_native=$(sed -n 's/^| Native run | \(fails\).* |$/\1/p' "$readme" | head -1)
    [[ -z $command || -z $answer ]] && { echo "skip  $name (no command or answer)"; continue; }
    binary=${command%% *}
    if [[ ! -f $binary ]]; then
        echo "skip  $name (run examples/fetch.sh)"
        continue
    fi
    started=$(date +%s)
    output=$(eval "uv run ppy-rev solve $command ${verify:-}" 2>&1)
    seconds=$(($(date +%s) - started))
    native=$(sed -n 's/.*native (sandboxed): \([a-z]*\).*/ \1 natively/p' <<<"$output" | head -1)
    [[ $native == " failed natively" && -n $expected_native ]] && native=" failed natively (documented)"
    if grep -qF -- "$answer" <<<"$output" && [[ -z $verify || $native != " failed natively" ]]; then
        printf 'ok    %-28s %3ds%s\n' "$name" "$seconds" "$native"
    else
        printf 'FAIL  %-28s %3ds  %s\n' "$name" "$seconds" "$(grep -A1 '^Solution' <<<"$output" | tail -1)"
        failures=$((failures + 1))
    fi
done

echo "$failures failing"
[[ $failures -eq 0 ]]

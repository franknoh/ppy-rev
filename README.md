# ppy-rev

`ppy-rev` lifts ELF binaries through Ghidra into a small typed intermediate
representation (RevIR), emits readable [PPy](https://github.com/franknoh/PPy),
and solves reversing challenges with purpose-built symbolic execution over Z3.

## Supported targets

Linux ELF, x86-64, little-endian. 32- and 64-bit floating point is modeled exactly, in the
solver and in the interpreter; x87's 80-bit format and processor-specific user operations
are lifted as explicit unsupported operations rather than approximated.
[What it can and cannot solve](docs/scope.md) describes the kinds of challenge this covers,
measured on 1,796 binaries from past CTFs.

## Installation

Requires Python 3.12, [uv](https://docs.astral.sh/uv/), a JDK 21, and
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.1.3.

```bash
uv tool install git+https://github.com/franknoh/ppy-rev    # or: uv tool upgrade / uninstall
ppy-rev --version
```

To work on the code instead, clone the repository and use its environment — `uv run ppy-rev
...`, or plain `ppy-rev` with `.venv` activated:

```bash
git clone https://github.com/franknoh/ppy-rev
cd ppy-rev && uv sync --frozen
```

Then run `ppy-rev doctor` once: it finds a Ghidra installation on the machine, asks before
saving it to `~/.ppy-rev`, and checks the other tools it needs (a JDK 21, Z3), so later runs
need nothing set up.

```bash
ppy-rev doctor          # find Ghidra, confirm, and save it; -y skips the prompt
```

`$PPY_REV_GHIDRA_HOME` overrides the saved path, and `--ghidra-home PATH` sets it for a
single run. `ppy-rev` never downloads Ghidra itself; the Docker image (`docker compose
build`) contains a checksum-verified one and every tool the test suite needs.

## Usage

```bash
ppy-rev info ./chall       # architecture, entry point, sections, functions
ppy-rev analyze ./chall    # inputs, likely outcomes, flag format, relevant code, VMs
ppy-rev solve ./chall      # find an input that reaches the success output, and verify it
ppy-rev lift ./chall       # lift to RevIR or emit runnable PPy   (docs/emit-ppy.md)
ppy-rev vm detect ./chall  # find and lift a bytecode interpreter (docs/vm.md)
```

A typical session: `analyze` shows what solving will work with (where the input comes from,
which strings look like success or failure, whether code runs before `main`, whether there
is a bytecode VM); `solve` then searches for an input that reaches the success output,
checks it by running the lifted program, and prints it. When the guesses are right, that is
all it takes. When they are not, tell it what you know — `--argv 2`/`--stdin 64`,
`--goal-string`, `--flag-format 'CTF{*}'`, `--length`, `--timeout` — and read the answer
with `--output answer.bin` (`--verify` also runs the binary on it in a locked-down
container). `solve` exits 0 only when it found an answer; `-v` shows why it chose the input
and goal, and what the search did. The full reference is in **[docs/solving.md](docs/solving.md)**.

## Examples

Sixty real CTF challenges, from picoCTF to Google CTF, are in
[`examples/`](examples/README.md), each with its own walkthrough; most need no options at
all, and `examples/check.sh` re-solves every one.

```bash
examples/fetch.sh                                        # download the original binaries
uv run ppy-rev solve examples/ais3_crackme/ais3_crackme  # prints ais3{I_tak3_g00d_n0t3s}
```

**A crackme** — symbolic execution finds the input and re-runs the lifted program to check
it:

```text
$ ppy-rev solve ./chall
Input:
  argv[1]
Goal:
  reaches 0x1010b7 — calls puts("Correct!")
Solution:
  rev_is_easy
Verification:
  RevIR execution: passed (reaches the goal)
```

**A bytecode VM** — recover the bytecode and solve against it, not the dispatch loop
([docs/vm.md](docs/vm.md)):

```bash
ppy-rev vm detect ./chall    # confirm an interpreter, with evidence
ppy-rev vm solve ./chall     # solve over the lifted bytecode; verified on the interpreter
```

**A binary bomb** — detect the phases and the failure sink, solve each, and chain the
answers into one input that defuses the whole thing ([docs/chain.md](docs/chain.md)):

```bash
ppy-rev solve ./bomb --chain --output solution
./bomb < solution            # Congratulations! You've defused the bomb!
```

**Runnable PPy** — emit source that reproduces the program, optionally carrying the answer
([docs/emit-ppy.md](docs/emit-ppy.md)):

```bash
ppy-rev lift ./chall --emit-ppy --mode solved -o out
ppy out/program.ppy          # runs with no arguments and reaches the goal
```

## Python API

```python
from pathlib import Path

from ppy_rev import Analyzer, SolveRequest

result = Analyzer().solve(SolveRequest(binary=Path("chall"), goal_string="Correct!"))
print(result.status, [solution.argv for solution in result.solutions])
```

`Analyzer` also provides `info`, `analyze`, `lift`, and `simplify`; the VM tools are in
`ppy_rev.vm.detect` and `ppy_rev.vm.lift`. Results are typed dataclasses; no Z3 or Ghidra
objects cross the API.

## Development

```bash
scripts/check.sh                    # ruff, pyright, Java bridge build, pytest
scripts/build_fixtures.sh           # compile C fixtures with gcc/clang at -O0..-O3
uv run python scripts/benchmark.py  # time Ghidra, lifting, simplification, slicing, search, SMT
examples/check.sh                   # solve the CTF examples and compare with their answers
VERIFY=1 examples/check.sh          # and run each answer on the real binary, in a container
docker compose build && docker compose run --rm dev scripts/check.sh
```

Tests that need Ghidra or a compiler are skipped when the tool is missing, unless
`PPY_REV_REQUIRE_TOOLS=1` (set in the Docker image) turns that into a failure.
`PPY_REV_UPDATE_GOLDEN=1` rewrites golden RevIR after an intentional change. Container
isolation tests run when `PPY_REV_SANDBOX_IMAGE` names a local image. The internals —
Ghidra bridge, lifter, simplifier, interpreter, symbolic engine, library models, analysis,
VM tools — are laid out in **[docs/architecture.md](docs/architecture.md)**.

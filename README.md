# ppy-rev

`ppy-rev` lifts ELF binaries through Ghidra into a small typed intermediate
representation (RevIR), emits readable [PPy](https://github.com/franknoh/PPy),
and solves simple reversing challenges with purpose-built symbolic execution
over Z3.

## Supported targets

Linux ELF, x86-64, little-endian. Floating-point p-code and processor-specific
user operations are lifted as explicit unsupported operations rather than
approximated.

## Installation

Requires Python 3.12, [uv](https://docs.astral.sh/uv/), a JDK 21, and
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.1.3.

```bash
uv sync --frozen
export PPY_REV_GHIDRA_HOME=/path/to/ghidra_12.1.3_PUBLIC
```

`ppy-rev` never downloads Ghidra itself. The Docker image (`docker compose build`)
contains a checksum-verified Ghidra and every tool the test suite needs.

## Commands

```bash
ppy-rev info ./chall                # architecture, entry point, sections, functions
ppy-rev analyze ./chall             # inputs, likely outcomes, relevant code, VMs, diagnostics
ppy-rev lift ./chall --emit-ir      # simplified RevIR for every recovered function (--no-simplify: raw)
ppy-rev lift ./chall --emit-ir --function main -o main.revir
ppy-rev lift ./chall --emit-ppy -o out --check-ppy
ppy-rev solve ./chall               # find an input that reaches the success output
ppy-rev vm detect ./chall           # find bytecode interpreter dispatchers, with evidence
ppy-rev vm lift ./chall             # translate the bytecode to RevIR; --json writes the ISA
ppy-rev vm solve ./chall            # solve with the interpreter replaced by lifted bytecode
```

`--emit-ppy` writes `out/module.ppy` (every lifted function plus the program image),
`out/runtime.ppy` (memory model and exact fixed-width helpers), and
`out/metadata.json` (function interfaces). Values are masked machine integers with
PPy fixed-width annotations; `--check-ppy` runs `ppy check` and fails if PPy reports
an error or has to insert a runtime width check. Functions with more than one block use
explicit block dispatch, so arbitrary control flow is preserved exactly.

Ghidra analysis runs headlessly in a throwaway project. Validated exports are
cached under `$PPY_REV_CACHE_DIR` (default `~/.cache/ppy-rev`), keyed by the
binary's SHA-256, the Ghidra version, the export bridge sources, and the
analysis options; `--no-cache` forces a fresh analysis, and `ppy-rev cache clear`
deletes them.

### Solving

```text
$ ppy-rev solve ./chall
Target: x86-64 Linux ELF

Input:
  argv[1]
  inferred length: 11

Goal:
  reaches 0x1010b7
  calls puts("Correct!")
  ...
Solver:
  backend: z3
  result: sat

Solution:
  rev_is_easy

Verification:
  RevIR execution: passed (reaches the goal)
```

`solve` finds `main`, discovers which inputs the program reads (`argv[k]` by following
where the argv pointer flows; stdin through `read`, `fgets`, `getchar`, `scanf`), and ranks
printed strings as likely success or failure outcomes. The goal is the call that prints
the success string *with that string as its argument*, so branchless selection of the
message (`cmov`) is handled. Symbolic execution then searches paths with the fewest
symbolic decisions first, pruning states that can no longer reach the goal and merging
the paths of loop-free branch regions where they join (inside a loop, paths that leave
the loop continue on their own). A backward slice from the goal skips work that cannot
matter: messages printed along the way, and helper functions that only print. Library calls use models of the
C functions crackmes typically use (`strlen`, `strcmp`, `memcmp`, `read`, `fgets`,
`scanf`, `atoi`/`strtol`, `isalpha`/`toupper` and the ctype tables, `puts`, `printf`,
`exit`, ...), checked against glibc by differential tests. Where a model approximates,
the result says so, and an approximation that could hide paths turns `unsat` into
`analysis incomplete`. Every solution is re-run on the concrete RevIR interpreter before
it is reported, and the shortest argv string is preferred.

Discovery can be overridden: `--argv INDEX` or `--stdin LENGTH`, `--goal-address` or
`--goal-string`, `--avoid-address`/`--avoid-string`. Constraints are never assumed
unless given: `--length`, `--max-length` (default 64 for argv; stdin defaults to 256
bytes), `--prefix`, `--charset {printable,ascii,alnum,alpha,digits,hex}`. Printable
solutions are preferred but not required. `--solutions N` asks for distinct inputs,
`--output FILE` writes the first one's raw bytes, `--emit-smt2 [FILE]` the goal path's
constraints as SMT-LIB,
and `-v`/`-vv` show evidence, statistics, and path constraints. Limits: `--timeout`
seconds and `--max-states`.

When symbolic search ends without an answer (a budget, or a symbolic pointer too wide to
model), `solve` falls back to concolic search (`--strategy auto`, the default; `symbolic`
or `concolic` pick one). Concolic search runs the program on a concrete seed input
(`--seed TEXT`, or any input the constraints allow), records the choices that input did
not take, and turns the most promising one into the next seed with the solver, deepest
choices and uncovered code first. A too-wide pointer is fixed to its seed value; that is
reported as an approximation, so a search that finds nothing is not reported as `unsat`.

`--verify` additionally runs each solution natively, and only then: a copy of the
binary runs under Docker or Podman with no network, a read-only root file system, no
capabilities, an unprivileged user, and memory, process, CPU, time, and output limits.
The image (`--sandbox-image`, default `ubuntu:24.04`) must already exist locally; it is
never pulled.

The result is `sat`, `unsat` (every path was explored within the input bounds),
`unknown`, `timeout`, `budget exhausted`, `analysis incomplete`, or `unsupported
semantics`; only `sat` exits with status 0. Unknown solver results and unmodeled
semantics on a relevant path are reported as such, never as `unsat`. Without
`--verify`, the target binary is never executed.

### VM dispatchers

`vm detect` looks for bytecode interpreters: a group of branches (a jump table, or a
chain or tree of comparisons) deciding on one value fetched from memory, inside a loop its
handlers return to. Each candidate lists the opcode fetch, the VM program counter (a
memory field or a loop variable), the bytecode base when it is a constant, the handlers
with the opcode values proven to select them, and its evidence, each item marked
`proven` (follows from RevIR), `inferred`, or `heuristic`. Candidates below 0.6
confidence, typically ordinary `switch` statements, are shown with `--all`.

`vm lift` finds a path from `main` into the interpreter, takes the state there, and
specializes the interpreter to its bytecode by partial evaluation of RevIR: the program
counter is always known, so each trip around the dispatch loop becomes the RevIR of one
bytecode instruction, while everything depending on input stays as residual code. It
prints the recovered instruction set (neutral names such as `op_0b`, lengths, handlers,
branches, exits) and each instruction's bytes, successors, and effects over the
interpreter's state; `--emit-ir` prints the lifted function and `--json` writes the
description. Facts taken from the entry state (the state pointer, the bytecode pointer)
are checked by guards at the start of the lifted function, which stops instead of
misbehaving in any other state.

`vm solve` runs `solve` with calls to the interpreter replaced by the lifted bytecode
function, then re-verifies every solution on the original interpreter. It accepts the
same options as `solve`.

## Architecture

```text
ELF ─► Ghidra headless ─► versioned JSON export ─► RevIR (SSA) ─► consumers
```

- `ppy_rev.ghidra`: the Java export bridge (`bridge/*.java`, extraction only),
  the headless runner, the export schema parser, and the cache.
- `ppy_rev.lift`: raw p-code → RevIR. Control flow is recovered at p-code
  granularity; registers and temporaries become SSA values; calls and returns
  carry register state explicitly.
- `ppy_rev.ir`: the immutable RevIR model, its reference concrete semantics, text
  form, CFG utilities, and a structural validator (single definitions, dominance,
  operation widths).
- `ppy_rev.simplify`: interprocedural register-interface narrowing, constant folding
  with width-exact identities, common subexpression elimination, block-local
  store/load forwarding, dead code elimination, and CFG cleanup. Operations that
  may fault are never removed.
- `ppy_rev.execution`: a strict concrete RevIR interpreter with an explicit memory
  model. It is the semantic oracle: tests compare it against native execution of
  the same compiled code, before and after simplification.
- `ppy_rev.symbolic` and `ppy_rev.solver`: symbolic execution of RevIR over
  hash-consed bit-vector expressions, with a narrow solver interface and a Z3
  backend. Pointers that are symbolic over a small range (bounded syntactically or by
  the path condition) are modeled exactly; wider ones stop exploration with a
  diagnostic. Division by a symbolic divisor constrains it to be non-zero, since RevIR
  division faults.
- `ppy_rev.summaries`: C library models, concrete (for the interpreter) and symbolic,
  tested against each other.
- `ppy_rev.analysis`: whole-program facts for solving: `main`, input discovery, goal
  ranking from strings, goal reachability, backward slicing, and the `analyze` report.
- `ppy_rev.vm`: bytecode interpreters: dispatcher detection, specialization of the
  interpreter to its bytecode (VM lifting), and the instruction set description.
- `ppy_rev.verify`: sandboxed native execution for `solve --verify`.
- `ppy_rev.ppy`: PPy emission and validation with `ppy check`.

RevIR values have explicit bit widths; signedness belongs to operations.
Lifting is based on raw p-code (exact instruction semantics); Ghidra's
decompiler output (high p-code, prototypes, symbols) is exported alongside it
as metadata.

## Development

```bash
scripts/check.sh                    # ruff, pyright, Java bridge build, pytest
scripts/build_fixtures.sh           # compile C fixtures with gcc/clang at -O0..-O3
docker compose build && docker compose run --rm dev scripts/check.sh
```

Tests that need Ghidra or a compiler are skipped when the tool is missing,
unless `PPY_REV_REQUIRE_TOOLS=1` (set in the Docker image) turns that into a
failure. `PPY_REV_UPDATE_GOLDEN=1` rewrites golden RevIR after an intentional
change. Container isolation tests run when `PPY_REV_SANDBOX_IMAGE` names a local image.

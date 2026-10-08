# Solving

`ppy-rev solve ./chall` searches for an input that reaches a program's success output,
checks the answer by running the lifted program, and prints it. This is the full reference;
the [README](../README.md) has the short version, and [scope.md](scope.md) describes the
kinds of challenge it does and does not cover.

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

## What it does

`solve` finds `main`, discovers which inputs the program reads (`argv[k]` by following
where the argv pointer flows; stdin through `read`, `fgets`, `getchar`, `scanf`), and ranks
printed strings as likely success or failure outcomes. The goal is the call that prints the
success string *with that string as its argument*, so branchless selection of the message
(`cmov`) is handled. Symbolic execution then searches paths with the fewest symbolic
decisions first, pruning states that can no longer reach the goal and merging the paths of
loop-free branch regions where they join (inside a loop, paths that leave the loop continue
on their own). A backward slice from the goal skips work that cannot matter: messages
printed along the way, and helper functions that only print.

Library calls use models of the C functions crackmes typically use (`strlen`, `strcmp`,
`strchr`, `memcmp`, `read`, `fgets`, `scanf`, `atoi`/`strtol`, `isalpha`/`toupper` and the
ctype tables, `puts`, `printf`, `exit`, ...), checked against glibc by differential tests.
`ptrace(PTRACE_TRACEME)` is left to the solver rather than assumed, so anti-debugging checks
are searched both ways and an answer that needs a debugger says so. Unoptimized C++ is
modeled as far as a `std::string` read with `std::getline` or `std::cin >>`, indexed and
compared, and printed through `std::cout`. A program that reads a file it names itself —
`fopen("flag.txt")` — has that file's contents solved for and reported with the answer.
Where a model approximates, the result says so, and an approximation that could hide paths
turns `unsat` into `analysis incomplete`. Every solution is re-run on the concrete RevIR
interpreter before it is reported, and the shortest argv string is preferred.

## Overriding discovery

Discovery is a guess; tell `solve` what you know when it is wrong.

| Situation | Options |
|---|---|
| The input is elsewhere | `--argv 2`, `--stdin 64` |
| No success message, or the wrong one | `--goal-string 'Nice'`, `--goal-address 0x1014d6`, `--avoid-string 'Nope'` |
| You know the flag format | `--flag-format 'flag{*}'`, or `--prefix` and `--suffix` |
| You know the length | `--length 33` |
| The answer is valid but not the flag | a flag format, `--charset printable`, `--solutions 5` |
| It runs out of time | `--timeout 600`, `--strategy concolic --seed 'flag{aaaa}'` |
| A bytecode interpreter checks the input | `ppy-rev vm detect`, then `ppy-rev vm solve` (see [vm.md](vm.md)) |
| A multi-stage check (a bomb's phases) | `--chain`, or `--from ADDRESS` per stage (see [chain.md](chain.md)) |

Constraints are never assumed unless given: `--length`, `--max-length` (default 64 for
argv; stdin defaults to 256 bytes), `--prefix`, `--suffix`,
`--charset {printable,ascii,alnum,alpha,digits,hex}`. For stdin, length, prefix, and suffix
describe the first line. `--flag-format 'CTF{*}'` is shorthand for `--prefix 'CTF{' --suffix
'}'`; when the program mentions a flag shape of its own and the answer does not match it,
`solve` says so. Printable solutions are preferred but not required, and the shortest answer
wins: the shortest argv string, the first line ending as early as the program allows.

## Output

`--solutions N` asks for distinct inputs, `--output FILE` writes the first one's raw bytes,
`--emit-smt2 [FILE]` the goal path's constraints as SMT-LIB, and `-v`/`-vv` show evidence,
statistics, and path constraints. `--output` writes exactly the bytes the program needs, so
`./chall "$(cat answer.bin)"` or `./chall < answer.bin` reproduces it.

Limits: `--timeout` (seconds), `--max-states`, `--max-steps`, `--max-call-depth`,
`--max-loop-iterations`, and `--solver-timeout`; running out of one is reported as such. A
long run does not go quiet. After ten seconds it writes a line to stderr every few seconds —
the phase, paths waiting, operations, solver calls, blocks reached, and how much of that
time went into the solver — and Ghidra reports while it is still analyzing. This is on when
stderr is a terminal; `--progress` and `--no-progress` decide it explicitly, and nothing on
stdout changes either way.

## Concolic fallback

When symbolic search ends without an answer (a budget, or a symbolic pointer too wide to
model), `solve` falls back to concolic search (`--strategy auto`, the default; `symbolic` or
`concolic` pick one). Concolic search runs the program on a concrete seed input (`--seed
TEXT`, or any input the constraints allow), records the choices that input did not take, and
turns the most promising one into the next seed with the solver, deepest choices and
uncovered code first. A too-wide pointer is fixed to its seed value; that is reported as an
approximation, so a search that finds nothing is not reported as `unsat`.

For a small input a check keeps opaque to the solver — a hash against a constant, a table it
cannot invert — `--strategy brute` runs every value concretely instead; bound it with
`--charset` and `--length` (four hex digits is 65k tries, a second or two), since blind
printable brute force only reaches two or three bytes in the budget.

## Native verification

`--verify` additionally runs each solution natively, and only then: a copy of the binary
runs under Docker or Podman with no network, a read-only root file system, no capabilities,
an unprivileged user, and memory, process, CPU, time, and output limits. The image
(`--sandbox-image`, default `ubuntu:24.04`) must already exist locally; it is never pulled.
Without `--verify`, the target binary is never executed.

## Before `main`, and result statuses

Solving starts at `main`, so a constructor in `.init_array` that reads the input itself,
looks for a debugger, or exits is not modeled; when a binary has one, `solve` and `analyze`
say which library functions it reaches, because it can decide the outcome before `main`
runs.

The result is `sat`, `unsat` (every path was explored within the input bounds), `unknown`,
`timeout`, `budget exhausted`, `analysis incomplete`, or `unsupported semantics`; only `sat`
exits with status 0. Unknown solver results and unmodeled semantics on a relevant path are
reported as such, never as `unsat`. Unsupported semantics on a path that matters is a
missing model, not a wall: the name of the function is in the message.

## Caching

Ghidra analysis runs headlessly in a throwaway project. Validated exports are cached under
`$PPY_REV_CACHE_DIR` (default `~/.cache/ppy-rev`), keyed by the binary's SHA-256, the Ghidra
version, the export bridge sources, and the analysis options; `--no-cache` forces a fresh
analysis, and `ppy-rev cache clear` deletes them.

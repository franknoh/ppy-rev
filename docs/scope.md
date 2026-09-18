# What ppy-rev can and cannot solve

`ppy-rev` recovers the input to a *checker*: a program that reads something, decides whether
it is right, and says so. Everything it does — ranking printed strings into success and
failure outcomes, slicing away code that cannot matter, searching paths to the success call —
rests on that shape. When a binary has that shape and stays inside the modeled C library, a
solve is usually a second or two of analysis. When it does not, `ppy-rev` says what stopped
it rather than guessing.

## It solves

- **C crackmes that compare an input against a constant, a table, or a small computation**,
  byte by byte or as a whole: [ais3_crackme](../examples/ais3_crackme/README.md),
  [redpwn_check](../examples/redpwn_check/README.md),
  [b01lers_crackme](../examples/b01lers_crackme/README.md).
- **Input from `argv[1]` or stdin** — `read`, `fgets`, `gets`, `getchar`, `scanf`. The line
  length is discovered, not assumed; the shortest answer that works is preferred.
- **Arithmetic, xor, table lookups, ctype, `strlen`/`strcmp`/`memcmp`, `atoi`/`strtol`,
  `rand`/`srand`** (glibc's generator is modeled exactly), and the printing functions.
- **Loops and per-character checks**, including ones with several hundred constraints:
  [csaw_beleaf](../examples/csaw_beleaf/README.md) takes about three minutes,
  [tscctf_link_start](../examples/tscctf_link_start/README.md) under twenty seconds.
- **Bytecode VMs**, when a dispatcher is recognized: `ppy-rev vm` lifts the bytecode and
  solving continues through it ([thjcc_pocketvm](../examples/thjcc_pocketvm/README.md)).
- **Stripped binaries**, statically linked ones, and any optimization level: `main` is found
  through `__libc_start_main` when there is no symbol.

The 60 challenges in [`examples/`](../examples/README.md) are all of this kind; 55 of them
are solved with no options at all, and the other five need one hint each (a flag format, a
length, or a goal address).

## It does not solve

| Not solved | What you see |
|---|---|
| C++ with `std::string`/iostreams | `no likely success output found` — the message never reaches a call the ranker can read |
| Go, Rust | usually the same; their runtimes also bury `main` |
| Input from a file (`fopen`, `fread`) or a socket | `unsupported semantics` at the first call — there is no model for either |
| `sleep`/`signal`/`alarm`/`setjmp`, `time`-dependent behaviour | `unsupported semantics`; nondeterminism is not modeled |
| Self-modifying code, packers, `mprotect` tricks | no static call site to rank, or an unsupported operation |
| Floating point | lifted as explicit unsupported operations, never approximated |
| Programs that only print (no check) | `no likely success output found`: there is no input to recover |
| Anti-debug or environment checks *before* `main` | reported as `runs before main`, and not modeled — see [crewctf_ez_rev](../examples/crewctf_ez_rev/README.md) |

A missing C library model is the cheapest of these to hit and the cheapest to fix: one
beginner challenge in the survey below stops only because `getegid` has no model.

## Measured on 1,796 binaries

Every x86-64 Linux ELF in the reversing categories of the
[ctf-archives](https://github.com/sajjadium/ctf-archives) mirror was solved with a 60–90 s
budget and no hints, during development. Of 1,796 distinct binaries — 692 distinct
challenges, since two of them ship a thousand variants between them:

| share | outcome |
|---|---|
| 4.5% (81) | an answer (11.7% counting each challenge once) |
| 80% | no success string could be ranked — 71% of those are C++ iostreams, 20% print nothing recognizable |
| 6.3% | unsupported semantics — mostly `fopen` (28), signals and timing (15), `time`/`rand` (14) |
| 3.0% | ran out of budget — 29 to path explosion, 4 to genuinely hard constraint systems |
| 1.9% | `main` not found |
| 1.8% | no input source found |
| 1.5% | analysis incomplete |
| 0.4% | a crash in `ppy-rev` itself |
| 0.3% | `unsat` |

Of the 81 answers, 55 are solves worth the name: 4 failed `ppy-rev`'s own re-execution
check, 19 recovered nothing because the goal was reachable with no input at all, and 14
aimed at a string that turned out to be a prompt or a usage line rather than a success
message. Today's goal ranking rejects prompts and negations, so that last group is smaller
now, but the honest figure to quote from this survey is **55 of 1,796**. All 55 are plain C;
there is not one C++, Go, or Rust solve, and not one where the input came from a file or a
socket.

Time, wall clock including Ghidra: median 14 s, 90th percentile 37 s, longest 170 s. The
tool's own analysis is a fraction of that — median 0.8 s — so most of a short solve is
Ghidra, which is cached afterwards.

## What a failure is worth

- `unsat` means *every path within the given bounds* was explored. It is not a proof that no
  input exists: the bound on the input length, and any approximation noted in the output, are
  part of the claim. In this survey all six `unsat` results were on challenges that do have
  an answer.
- `unknown`, `timeout`, `budget exhausted`, `analysis incomplete` and `unsupported
  semantics` are never reported as `unsat`.
- Any approximation that could hide a path is printed as a `note:` and turns `unsat` into
  `analysis incomplete`. The most common one is *stdin after a symbolic-length `fgets` line
  is treated as empty*.
- A solution is re-run on the RevIR interpreter before it is reported; `--verify` also runs
  it on the real binary in a locked-down container. RevIR agreeing and the binary disagreeing
  is possible — [crewctf_ez_rev](../examples/crewctf_ez_rev/README.md) is exactly that case,
  and both lines are printed.

## When it fails, what to try

1. `ppy-rev analyze ./chall` first: it shows the inputs, the ranked strings, whether code
   runs before `main`, and whether there is a VM.
2. No success candidate? Name one: `--goal-string 'Correct'` or `--goal-address 0x…`. This
   is the single most useful override — four out of five failures above are a goal the tool
   would not guess, not a search it cannot do.
3. No input found? `--stdin LENGTH` or `--argv 1`.
4. Know the flag shape? `--flag-format 'ctf{*}'`, or `--prefix`/`--suffix`/`--length`.
5. Slow? Watch it work with `--progress`, raise `--timeout`, or try `--strategy concolic`.
6. Unsupported semantics on a path that matters is a missing model, not a wall: the name of
   the function is in the message.

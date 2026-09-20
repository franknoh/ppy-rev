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
- **Floating point**: `float` and `double` arithmetic, comparisons and conversions go to
  the solver as IEEE-754, so a check like `(double)c * 1.5 + 0.25 > 63.0` is solved rather
  than refused. Emitting such a program as PPy is still refused, since PPy stays integral.
  Floating point over a number parsed from text (`atoi` and then arithmetic on the result)
  is where the solver struggles: those queries can exceed `--solver-timeout`.
- **Loops and per-character checks**, including ones with several hundred constraints:
  [csaw_beleaf](../examples/csaw_beleaf/README.md) takes about three minutes,
  [tscctf_link_start](../examples/tscctf_link_start/README.md) under twenty seconds.
- **Bytecode VMs**, when a dispatcher is recognized: `ppy-rev vm` lifts the bytecode and
  solving continues through it ([thjcc_pocketvm](../examples/thjcc_pocketvm/README.md)).
- **A file the program reads**: `fopen` of a path the binary spells out makes that file's
  contents an input like any other, recovered and printed as `flag.txt: ...`; `fgets`,
  `fread`, `fgetc`, `fseek`, `ftell` and `rewind` read it, and what the program writes to a
  file it opened becomes that file's contents. The answer is checked by re-running the
  program against those contents; the sandboxed native run is skipped, since it would need
  the file written for it.
- **Hex encoding with `sprintf`**: `%02x`-style conversions are written out byte for byte,
  so a program that encodes its input and compares the text is solved. Conversions whose
  length depends on the value (`%d` of an unknown number) are refused instead of guessed.
- **Anti-debugging in `main`**: `ptrace(PTRACE_TRACEME)` is an environment the solver picks
  rather than an assumption, so a challenge that only reveals its answer under a debugger is
  solved, and the answer says it needs one.
- **C++, optimized or not**: input read with `std::getline` or `std::cin >>` into a
  `std::string` or a number, indexed, sized, compared, transformed, pushed into a
  `std::vector`, and printed through `std::cout`. `std::string` uses libstdc++'s own
  layout, so code that reads the object directly agrees with code that calls `size()` and
  `data()`, and which overload an import is comes from its mangled symbol rather than from
  a demangled name a C program could share. At `-O2` the library is inlined into loads of
  those same fields, and `std::cin` and `std::cout` are objects the code reads rather than
  calls, so they are laid out too: a stream in good state, with the `ctype` facet that
  inlined `getline` widens its delimiter with. The 14 C++ fixtures in `tests/fixtures/src`
  are solved under `g++` and `clang++`, at `-O0` and `-O2`, and every answer is checked
  against the compiled binary.
- **Code that runs before main**: the constructors in `.init_array` are executed on the
  image before solving starts, so a key table built by a global object, or a global
  `std::string`, is what main really reads. A constructor that would need the input — it
  reads, exits, or looks for a debugger — is not run, and is reported instead.
- **Stripped binaries** at any optimization level: `main` is found through
  `__libc_start_main` when there is no symbol.

The 60 challenges in [`examples/`](../examples/README.md) are all of this kind; 55 of them
are solved with no options at all, and the other five need one hint each (a flag format, a
length, or a goal address).

## It does not solve

| Not solved | What you see |
|---|---|
| A `std::string` whose length the input decides — `std::string s(argv[1])` | `unsupported semantics`: the allocation that follows needs a size, and guessing one would answer for a different program. A line read with `getline` is fine, since the object it fills is laid out here |
| Rust | the same: ten in the survey below, none solved |
| Go | not represented in the survey; its runtime does not reach `main` the way this expects |
| Input from a socket | `unsupported semantics` at the first call — there is no model |
| `sleep`/`signal`/`alarm`/`setjmp`, `time`-dependent behaviour | `unsupported semantics`; nondeterminism is not modeled |
| Self-modifying code, packers, `mprotect` tricks | no static call site to rank, or an unsupported operation |
| x87 80-bit long double | `unsupported semantics`; binary32 and binary64 are modeled exactly |
| Programs that only print (no check) | `no likely success output found`: there is no input to recover |
| Anti-debug or environment checks *before* `main` | reported as `runs before main`: a constructor that reads input, exits, or calls `ptrace` is not executed, since running it would decide for the input — see [crewctf_ez_rev](../examples/crewctf_ez_rev/README.md) |

A missing C library model is the cheapest of these to hit and the cheapest to fix: one
beginner challenge in the survey below stops only because `getegid` has no model.

## Measured on 1,796 binaries

x86-64 Linux ELF challenges were harvested from the reversing categories of the
[ctf-archives](https://github.com/sajjadium/ctf-archives) mirror over eight crawls during
development, and each was run through `ppy-rev solve` with a 60–90 s budget and no options
at all. Of 1,796 distinct binaries — only 692 distinct challenges, since two of them ship a
thousand variants between them:

| share | outcome |
|---|---|
| 4.5% (81) | an answer (11.7% counting each challenge once) |
| 80% | no success string could be ranked — 71% of those are C++ iostreams (which today's `std::ostream` model would rank), 20% print nothing recognizable |
| 6.3% | unsupported semantics — mostly `fopen` (28, modeled since), signals and timing (15), `time`/`rand` (14) |
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
socket. That survey predates every C++ model here, so its C++ figure is a floor, not a
ceiling; the section after next measures a fresh sample instead.

Time, wall clock including Ghidra: median 14 s, 90th percentile 37 s, longest 170 s. The
tool's own analysis is a fraction of that — median 0.8 s — so most of a short solve is
Ghidra, which is cached afterwards.

Two caveats on the method. None of these binaries was executed, so a `sat` result here means
only that the answer re-runs to the goal on the RevIR interpreter; of the 60 examples, which
*were* checked against the real binaries in a container, 58 pass and one is the documented
divergence above. And the outcome is not perfectly stable across versions: of 200 binaries
re-attempted after changes to the tool, 38 changed category — 4 became solvable, and 9 that
had been solved were not solved again.

## Measured again on 452 binaries

The survey above is from before the C++ work, and the binaries it ran on are gone, so the
measurement was repeated on a fresh sample from the same archive: every blob in a
reversing category between 5 KB and 400 KB with no file extension (553 of them), of which
452 are x86-64 ELF and 57 link libstdc++. Same method as before — a 90-second budget, no
options, and nothing executed.

| share | outcome |
|---|---|
| 62.2% (281) | no success string could be ranked |
| 12.2% (55) | unsupported semantics |
| 7.7% (35) | an answer |
| 4.6% (21) | `main` not found |
| 4.4% (20) | ran out of time |
| 3.8% (17) | no input source found |
| 1.8% (8) | a crash in `ppy-rev` itself |
| 1.3% (6) | `unsat` |
| 0.9% (4) | ran out of budget |
| 0.9% (4) | analysis incomplete |
| 0.2% (1) | `unknown` |

Of the 35 answers, 32 pass `ppy-rev`'s own re-execution check and 6 of those recovered
nothing, because the goal turned out to be reachable with no input at all. The remaining
26 were not audited for the failure mode the first survey found in 14 of its 81 answers —
a goal that was a prompt rather than a verdict — so **26 is an upper bound**, against 55
of 1,796 (and 55 of 692 distinct challenges) in the first survey. The two samples are not
the same binaries, and this one has no challenge shipping a thousand variants, so the
per-binary rates are not directly comparable; the per-challenge rate of the first survey,
8%, is the closer comparison.

What this says about the C++ work is narrower than the fixtures suggest. Of the 57 C++
binaries, 2 are solved — before this, none were — and the C++ *semantics* are no longer
what stops most of them: 32 of the 57 stop because nothing they print ranks as a success
message. That is the same wall the whole sample hits, and it is now the first thing worth
working on. Behind it, the models still missing most often are `std::ifstream` (5 of the
12 unsupported C++ runs), `std::string::erase`, `atof`, and C++ exceptions.

The 8 crashes are the other actionable result: one was the image setup writing a stream
pointer into read-only data, fixed here; 6 are one assertion in SSA construction
(`phi ... has no incoming value`) and 1 is a recursion limit, both still open.

The other side of the same coin: the 14 C++ fixtures in `tests/fixtures/src` — `getline`,
`cin >>`, indexing, sizing, comparison, `std::vector`, `std::array`, `std::transform`,
lambdas, global constructors — are all solved under `g++` and `clang++`, at `-O0` and
`-O2`, with every answer accepted by the compiled binary.

## What a failure is worth

- `unsat` means *every path within the given bounds* was explored. It is not a proof that no
  input exists: the bound on the input length, and any approximation noted in the output, are
  part of the claim. In this survey all six `unsat` results were on challenges that do have
  an answer.
- `unknown`, `timeout`, `budget exhausted`, `analysis incomplete` and `unsupported
  semantics` are never reported as `unsat`.
- Any approximation that could hide a path is printed as a `note:` and turns `unsat` into
  `analysis incomplete`. The most common one is *input after a symbolic-length `fgets` line
  is treated as empty*.
- A solution is re-run on the RevIR interpreter before it is reported; `--verify` also runs
  it on the real binary in a locked-down container. RevIR agreeing and the binary disagreeing
  is possible — [crewctf_ez_rev](../examples/crewctf_ez_rev/README.md) is exactly that case,
  and both lines are printed.

## When it fails, what to try

1. `ppy-rev analyze ./chall` first: it shows the inputs, the ranked strings, whether code
   runs before `main`, and whether there is a VM.
2. No success candidate? Name one: `--goal-string 'Correct'` or `--goal-address 0x…`. This
   is the single most useful override: four out of five failures above are a goal the tool
   could not name. For plain C that is usually the whole problem; for C++ it is only the
   first one — a `std::string` comparison stops the search right after.
3. No input found? `--stdin LENGTH` or `--argv 1`.
4. Know the flag shape? `--flag-format 'ctf{*}'`, or `--prefix`/`--suffix`/`--length`.
5. Slow? Watch it work with `--progress`, raise `--timeout`, or try `--strategy concolic`.
6. Unsupported semantics on a path that matters is a missing model, not a wall: the name of
   the function is in the message.

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
  [tscctf_link_start](../examples/tscctf_link_start/README.md) under twenty seconds. When
  each character is checked through a helper that validates it and calls `exit` on a bad
  one, the two sides of that check meet again and are merged, so the loop costs one path
  per character instead of one per combination of them — the difference between solving in
  a minute and never finishing.
- **Bytecode VMs**, when a dispatcher is recognized: `ppy-rev vm` lifts the bytecode and
  solving continues through it ([thjcc_pocketvm](../examples/thjcc_pocketvm/README.md)).
- **A file the program reads**: `fopen`, or `std::ifstream` of a path the binary spells
  out, makes that file's contents an input like any other, recovered and printed as
  `flag.txt: ...` (and written by `--output`). `std::getline(file, line)` reads that file
  rather than the terminal, and what a file has to contain runs to the last byte the
  program looked at — a file is not a C string, so a zero byte in the middle of it is
  part of the answer. `fgets`, `fread`, `fgetc`, `fseek`, `ftell` and `rewind` read it, and what the program writes to a
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
  against the compiled binary. A string whose length the input decides — `std::string
  s(argv[1])` — is built as such: the copy that follows writes each byte only where it is
  really part of the string, so nothing has to be assumed about how long the input is.
- **Code that runs before main**: the constructors in `.init_array` are executed on the
  image before solving starts, so a key table built by a global object, or a global
  `std::string`, is what main really reads. A constructor that would need the input — it
  reads, exits, or looks for a debugger — is not run, and is reported instead.
- **Programs that read the clock**: `time` returns a second the solver picks, reported with
  the answer (`needs the clock to read ...`) rather than assumed here, and `sleep`,
  `usleep` and `alarm` pass. A seed the clock decides — `srand(time(NULL))` — is settled
  on one value it could take, which is said in a note and turns a fruitless search into
  `analysis incomplete` rather than `unsat`. `signal` installs a handler that is never
  called, since nothing here raises one.
- **An outcome with nothing to read in it**: when no message ranks as success, the goal
  is looked for by shape instead — a call that prints, or a success status the program
  leaves with, that the input decides it reaches. Plenty of checkers say nothing at all:
  passing is returning zero. The input is followed across calls and through a call table,
  since the deciding usually happens in a function `main` handed the buffer to. That is language-independent, so it
  covers a flag spelled out with `putc`, a message built while running, and the runtimes
  of Rust, Go and Nim, whose strings a C-string reader cannot see. The evidence is
  printed with the candidate, and an answer that turns out to reach the goal without
  reading the input at all says so.
- **Messages given as a pointer and a length**, as Rust and Go give them: read to that
  length rather than to the next zero byte, which in those binaries runs through several
  messages at once.
- **Stripped binaries** at any optimization level: `main` is found through
  `__libc_start_main` when there is no symbol.

The 60 challenges in [`examples/`](../examples/README.md) are all of this kind; 55 of them
are solved with no options at all, and the other five need one hint each (a flag format, a
length, or a goal address).


## Merging per-character checks that branch

A common crackme shape checks the input one character at a time, and after each character
takes a branch — a compare against a table, a helper that rejects bytes out of range by
calling `exit`. Explored naively, the branches multiply: a 29-character check is half a
billion paths. Diamonds like these, whose sides meet again with no loop of their own, are
now explored to that meeting point and merged into a single state, and the merge sees
through a branch side that ends the program and through the two loops clang emits at `-O2`
for a check that must keep running after one character fails. Values live only earlier in
the loop no longer keep the merge apart. A path the solver cannot settle at the join — the
whole check at once is a hard query — is kept rather than dropped, so a slow query never
turns into a false "no input works".

Measured against the commit before this work, on a hundred variants of one such challenge
(GreyCat's *AngryRobot*, a 29-byte per-character modular check), none solved before and all
hundred solve now, every answer accepted by the program's own re-execution. On a
40-binary sample of unrelated challenges the change is neutral: the same outcomes, nothing
lost.

## It does not solve

| Not solved | What you see |
|---|---|
| Rust | its `fmt::Arguments` machinery is not modeled, so a message assembled from pieces is not read; the outcome can still be found by its shape (see above) |
| Go | its runtime does not reach `main` the way this expects |
| Input from a socket | `unsupported semantics` at the first call — there is no model |
| `setjmp`, and a signal actually being delivered | `unsupported semantics`; a handler that is installed but never runs is fine (see above), one the program raises is not |
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
| 55.8% (252) | no success string could be ranked, and no outcome found by its shape |
| 11.9% (54) | unsupported semantics |
| 9.5% (43) | an answer |
| 6.2% (28) | `main` not found |
| 4.4% (20) | ran out of time |
| 4.0% (18) | no input source found |
| 3.8% (17) | analysis incomplete |
| 2.2% (10) | `unsat` |
| 2.2% (10) | ran out of budget, or something else |

Nothing crashed: the 8 crashes the first run of this sample hit are fixed, as described
below, and each of those binaries now reports why it stopped.

Of the 43 answers, 38 pass `ppy-rev`'s own re-execution check and 8 of those recovered
nothing, because the goal turned out to be reachable with no input at all — which the
output now says. That leaves **31 answers worth the name**, against 27 before outcomes
could be found by their shape, and 55 of 1,796 (55 of 692 distinct challenges) in the
first survey. The two samples are not the same binaries, and this one has no challenge
shipping a thousand variants, so the per-binary rates are not directly comparable; the
per-challenge rate of the first survey, 8%, is the closer comparison.

Finding outcomes by shape moved 30 binaries out of the largest bucket: 11 of them to an
answer — among them `BITSCTF{w3lc0me_t0_r3v}` and `TooEasyForTheFirstFlag`, which no
keyword would have reached — and the rest to a reason the analysis can name, such as an
unsupported call or a search that ran out of time. It also costs something: `unsat` went
from 6 to 10, and those are about a goal chosen by how it is reached rather than by what
it says, which the output says when it reports one.

What this says about the C++ work is narrower than the fixtures suggest. Of the 57 C++
binaries, 2 are solved — before this, none were — and the C++ *semantics* are no longer
what stops most of them: 32 of the 57 stop because nothing they print ranks as a success
message. That is the same wall the whole sample hits, and it is now the first thing worth
working on. Behind it, the models still missing most often are `std::ifstream` (5 of the
12 unsupported C++ runs), `std::string::erase`, `atof`, and C++ exceptions.

The 8 crashes were the other actionable result, and every cause is fixed. The image setup
wrote a stream pointer into read-only data, which is a relocation and so does not need the
program's permission. Six were a function *entered inside its own loop*: the code before
the entry falls into it, so the entry block had a predecessor, and a value carried around
that loop had nowhere to come from on the way in. The entry now gets an empty block of its
own, as it already did when a branch targeted it — without one, the phi for such a value is
replaced by a definition that reads it, which is both wrong and unbounded work for the
simplifier, so a 15 KB binary took minutes. Should a phi still turn up with no incoming
value at all, it is the value the caller left rather than an assertion, and following an
address through a value defined from itself now stops. The last crash was a function whose
branches nested deeper than Python's recursion limit, which lifting now raises, reporting
the function as unliftable if it ever runs out anyway. Re-running the whole sample
afterwards changed nothing else: seven of the eight now report `main` not found and one
reports unsupported semantics, and every other binary landed where it had before.

The other side of the same coin: the 16 C++ fixtures in `tests/fixtures/src` — `getline`,
`cin >>`, indexing, sizing, comparison, `std::vector`, `std::array`, `std::transform`,
lambdas, global constructors, a string built from `argv[1]` — are all solved under `g++`
and `clang++`, at `-O0` and `-O2`, with every answer accepted by the compiled binary.

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

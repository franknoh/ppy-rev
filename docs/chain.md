# Multi-stage challenges

A binary bomb reads its input one line at a time and gates each line on a separate check — a
*phase* — that calls a shared failure handler (`explode_bomb`) when the line is wrong. The
whole input is only right when every phase is. `ppy-rev` solves these two ways: one phase at
a time with `--from`, or the whole thing at once with `--chain`.

## `--chain`: the whole bomb at once

```text
$ ppy-rev solve ./bomb --chain -v
...
note: staged driver: 6 phases, sink explode_bomb at 0x40143a, reading each line with read_line
note: phase_1 at 0x400ee0: solved, line b'Border relations with Canada have never been better.'
note: phase_2 at 0x400efc: solved, line b'1 2 4 8 16 32'
note: phase_3 at 0x400f43: solved, line b'1 311'
note: phase_4 at 0x40100c: solved, line b'7 0'
note: phase_5 at 0x401062: solved, line b'\t\x0f\x0e\x05\x06\x07'
note: phase_6 at 0x4010f4: solved, line b'4 3 2 1 6 5'

Verification:
  RevIR execution: passed (reaches the goal)
```

`--chain` detects the staged driver on its own: the shared failure **sink** is the internal
function the most phases call and that itself ends the program (`exit`/`abort`), found by
call-count without needing a symbol named `explode_bomb`; the **line reader** is the
function that reads stdin, directly or through a helper (a bomb's `read_line` reads through
`skip`→`fgets`); and the **phases** are the functions `main` calls exactly once that can
reach the sink. It then solves each phase in isolation (as `--from` does below), keeps every
answer to one line, joins them with newlines, and re-runs the whole program on the combined
input to confirm it reaches the success message. A phase the solver cannot crack stops the
chain; the phases solved before it are still reported.

Write the combined input and run the real binary on it:

```bash
ppy-rev solve ./bomb --chain --output solution
./bomb < solution        # Congratulations! You've defused the bomb!
```

### Number phases

A phase that reads several integers (`sscanf(line, "%d %d %d %d %d %d", ...)`) would make
one heavy solver query if parsed from the buffer bytes. In a chain (and under `--from
--scanf-havoc`), a numeric `sscanf` is not parsed: the stage is handed fresh symbolic
integers and the count, its checks constrain those integers as plain arithmetic, and the
answer is rendered as a decimal line the real `sscanf` reads back to the same values. A
recurrence phase then solves in a moment. This skips the raw buffer, so a stage that also
inspects the string it read is the case it does not cover — the whole-program re-run catches
it.

## `--from`: one stage on its own

`--from ADDRESS` starts execution at a function with a symbolic buffer in its first
argument, so a single check or phase is solved by itself — the way `--chain` solves each
one, exposed for when detection needs a hand or only one stage matters.

```bash
ppy-rev solve ./bomb --from 0x400ee0 --avoid-address 0x40143a
#   solve phase_1 alone; return without reaching explode_bomb
```

Pair it with `--avoid-address` for the failure handler. Do not pass `--length` unless the
exact length is known — it forbids the terminating NUL a string compare needs. For a
number-heavy stage, add `--scanf-havoc` so its `sscanf` is solved as arithmetic.

## Scope

This covers the bomb shape: one line read per phase, phases sharing a failure sink, each
phase independent of the others. A phase that depends on a global an earlier phase set (a
`secret_phase` reached only after the rest) is out of scope, and so is a phase that inspects
its raw line beyond the numbers it parsed; the whole-program re-run at the end is what tells
you when a stage fell outside what the chain modeled.

---

The bomb example here was worked out against [qwoqLab](https://github.com/Aplace0927/qwoqLab)
— thanks for the reference.

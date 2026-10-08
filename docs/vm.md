# Bytecode VMs

Some challenges hide their check inside a small bytecode interpreter: the real logic is a
program in a made-up instruction set, and the binary only ships the interpreter plus the
bytecode. `ppy-rev vm` finds the interpreter, recovers the bytecode as straight-line RevIR,
and solves against that instead of the dispatch loop.

```bash
ppy-rev vm detect ./chall           # find interpreter dispatchers, with evidence
ppy-rev vm lift ./chall             # translate the bytecode to RevIR; --json writes the ISA
ppy-rev vm solve ./chall            # solve with the interpreter replaced by lifted bytecode
```

## `vm detect`

```text
$ ppy-rev vm detect ./chall
Candidate dispatcher: fetch at 0x11f0, pc = loop variable, confidence 0.86
  [proven]    indirect branch at 0x1204 on 1 value fetched from memory
  [proven]    VM program counter: loop variable advanced by each handler
  [inferred]  14 handlers, opcodes 0x00..0x0d
  ...
```

`vm detect` looks for a group of branches (a jump table, or a chain or tree of comparisons)
deciding on one value fetched from memory, inside a loop its handlers return to, that
decodes instructions: handlers advance the program counter by different amounts or read
operands after the opcode. Each candidate lists the opcode fetch, the VM program counter (a
memory field or a loop variable), the bytecode base when it is a constant, the handlers with
the opcode values proven to select them, and its evidence, each item marked `proven`
(follows from RevIR), `inferred`, or `heuristic`. Candidates below 0.6 confidence, typically
ordinary `switch` statements and loops that branch on each byte of their input, are shown
with `--all`.

## `vm lift`

`vm lift` finds a path from `main` into the interpreter, takes the state there, and
specializes the interpreter to its bytecode by partial evaluation of RevIR: the program
counter is always known, so each trip around the dispatch loop becomes the RevIR of one
bytecode instruction, while everything depending on input stays as residual code. It prints
the recovered instruction set (neutral names such as `op_0b`, lengths, handlers, branches,
exits) and each instruction's bytes, successors, and effects over the interpreter's state;
`--emit-ir` prints the lifted function and `--json` writes the description. Facts taken from
the entry state (the state pointer, the bytecode pointer) are checked by guards at the start
of the lifted function, which stops instead of misbehaving in any other state.

## `vm solve`

`vm solve` runs `solve` with calls to the interpreter replaced by the lifted bytecode
function, then re-verifies every solution on the original interpreter. It accepts the same
options as [`solve`](solving.md).

```text
$ ppy-rev vm solve ./chall
...
solved over 23 lifted bytecode instructions instead of the interpreter dispatch at 0x11f0;
verified on the original interpreter

Solution:
  vM_l1ft!
```

# Architecture

```text
ELF ─► Ghidra headless ─► versioned JSON export ─► RevIR (SSA) ─► consumers
```

- `ppy_rev.ghidra`: the Java export bridge (`bridge/*.java`, extraction only), the headless
  runner, the export schema parser, and the cache.
- `ppy_rev.lift`: raw p-code → RevIR. Control flow is recovered at p-code granularity;
  registers and temporaries become SSA values; calls and returns carry register state
  explicitly.
- `ppy_rev.ir`: the immutable RevIR model, its reference concrete semantics, text form, CFG
  utilities, and a structural validator (single definitions, dominance, operation widths).
- `ppy_rev.simplify`: interprocedural register-interface narrowing, constant folding with
  width-exact identities, common subexpression elimination, block-local store/load
  forwarding, dead code elimination, and CFG cleanup. Operations that may fault are never
  removed.
- `ppy_rev.execution`: a strict concrete RevIR interpreter with an explicit memory model. It
  is the semantic oracle: tests compare it against native execution of the same compiled
  code, before and after simplification.
- `ppy_rev.symbolic` and `ppy_rev.solver`: symbolic execution of RevIR over hash-consed
  bit-vector expressions, with a narrow solver interface and a Z3 backend. A symbolic
  pointer is resolved by asking the solver for the addresses it can take, or by bounding its
  range; when there are too many, symbolic exploration stops with a diagnostic (concolic
  search fixes them to a seed value instead). Division by a symbolic divisor constrains it
  to be non-zero, since RevIR division faults.
- `ppy_rev.summaries`: C library models, concrete (for the interpreter) and symbolic, tested
  against each other and against glibc, including its `rand`. Where a model forks on the
  shape of the input (how a number or a token ends), the alternatives are tests on single
  input bytes, decided without the solver.
- `ppy_rev.analysis`: whole-program facts for solving: `main`, input discovery, goal ranking
  from strings (prompts and complaints are not verdicts), flag shapes the program mentions,
  goal reachability, backward slicing, staged-driver detection, and the `analyze` report.
- `ppy_rev.vm`: bytecode interpreters: dispatcher detection, specialization of the
  interpreter to its bytecode (VM lifting), and the instruction set description.
- `ppy_rev.verify`: sandboxed native execution for `solve --verify`.
- `ppy_rev.ppy`: PPy emission and validation with `ppy check`, including the C library
  models and the front end that make an emitted program runnable.

RevIR values have explicit bit widths; signedness belongs to operations. Lifting is based on
raw p-code (exact instruction semantics); Ghidra's decompiler output (high p-code,
prototypes, symbols) is exported alongside it as metadata.

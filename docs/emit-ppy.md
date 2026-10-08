# Emitting PPy

`ppy-rev lift` turns a binary into [PPy](https://github.com/franknoh/PPy), readable
source that runs and reproduces what the program does.

```bash
ppy-rev lift ./chall --emit-ir                   # simplified RevIR for every function
ppy-rev lift ./chall --emit-ir --function main -o main.revir
ppy-rev lift ./chall --emit-ppy -o out --check-ppy
ppy-rev lift ./chall --emit-ppy --mode solved    # PPy that runs, carrying the answer
```

`--emit-ppy` writes `out/module.ppy` (every lifted function plus the program image),
`out/runtime.ppy` (the memory model, exact fixed-width helpers, and models of the C
functions the program imports), `out/program.ppy` (a front end that lays out `argv` and
standard input and calls the lifted `main`), and `out/metadata.json` (function interfaces).
`ppy out/program.ppy -- ARGUMENTS` runs the lifted program again, this time as PPy:

```text
$ echo | ppy out/program.ppy -- 'ais3{I_tak3_g00d_n0t3s}'
Correct! that is the secret key!
```

`--mode` decides how much of what ppy-rev worked out the emitted code carries:

| mode | what the output is |
|---|---|
| `raw` | RevIR exactly as p-code gave it, nothing folded away |
| `simplified` | the default: constants folded, dead code gone, library calls modeled |
| `vm` | the same, plus a bytecode VM's program lifted into a function beside its interpreter (see [vm.md](vm.md)) |
| `solved` | the same, plus the input solving found — `ppy out/program.ppy` then runs it with no arguments and reaches the goal |

Values are masked machine integers with PPy fixed-width annotations; `--check-ppy` runs `ppy
check` and fails if PPy reports an error or has to insert a runtime width check. Functions
with more than one block use explicit block dispatch, so arbitrary control flow is preserved
exactly.

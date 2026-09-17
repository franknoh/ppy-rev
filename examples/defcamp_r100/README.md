# r100 (Entry Language)

| | |
|---|---|
| Origin | DefCamp CTF Qualification 2015, Reverse 100 "Entry Language" ([binary via angr examples](https://github.com/angr/angr-doc/tree/master/examples/defcamp_r100)) |
| Binary | `r100`, x86-64 ELF, stripped |
| Input | stdin (`fgets`) |
| Hints needed | none (`--length 12` for the bare password) |
| Answer | `Code_Talkers` |

## The challenge

```text
$ ./r100
Enter the password: hunter2
Incorrect password!
```

The check compares the first 12 characters with three strings baked into the binary:

```c
char *p[3] = {"Dufhbmf", "pG`imos", "ewUglpt"};
for (i = 0; i < 12; i++)
    if (p[i % 3][2 * (i / 3)] - password[i] != 1) return 1;
```

The binary also has anti-debugging (`ptrace` and an `LD_PRELOAD` check) in a constructor
that runs before `main`.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/defcamp_r100/r100
```

```text
Input:
  stdin
  inferred length: 14

Goal:
  reaches 0x400849
  calls puts("Nice!")

Solver:
  backend: z3
  result: sat

Solution:
  Code_Talkers?_
```

About 7 seconds. Only 12 characters are checked, so anything may follow them: the
answer above is valid as it is. Add `--length 12` to get exactly `Code_Talkers`.

## How ppy-rev gets there

- **Input:** `main` calls `fgets` on stdin; the stdin model tracks exactly which bytes each
  read consumes.
- **Goal:** `"Nice!"` is picked as success (`nice`), `"Incorrect password!"` as failure.
- **Anti-debugging:** solving starts at `main`, so the constructor never runs and the
  `ptrace` trick plays no part. Nothing is ever executed natively unless you ask for
  `--verify`.
- **Search:** twelve comparisons, each with one side that leads to failure, then one solver
  call for the answer.

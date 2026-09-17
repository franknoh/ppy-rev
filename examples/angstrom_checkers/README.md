# checkers

| | |
|---|---|
| Origin | ångstromCTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/angstromCTF/2023/rev/checkers)) |
| Binary | `checkers`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `actf{ive_be3n_checkm4ted_21d1b2cebabf983f}` |

## The challenge

The joke is that the flag checker keeps the flag in one piece:

```c
fgets(input, 100, stdin);
if (strncmp(input, "actf{ive_be3n_checkm4ted_21d1b2cebabf983f}", 0x2a) == 0)
    puts("Correct!");
else
    puts("Wrong!");
```

`strings` finds it too; for `solve` it is one comparison like any other.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/angstrom_checkers/checkers
```

```text
Input:
  stdin
  inferred length: 42

Goal:
  reaches 0x10124d
  calls puts("Correct!")

Solver:
  backend: z3
  result: sat

Solution:
  actf{ive_be3n_checkm4ted_21d1b2cebabf983f}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Answer:** `strncmp` looks at 42 characters, and the line can end right after them, so
  the answer is exactly the flag.

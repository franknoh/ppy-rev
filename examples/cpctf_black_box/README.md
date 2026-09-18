# black box

| | |
|---|---|
| Origin | CPCTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/CPCTF/2024/rev/black_box)) |
| Binary | `chall`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `CPCTF{ConS7RucT_A_fl46_b0X}` |

## The challenge

The flag is rebuilt inside nested loops that scatter its characters through a matrix before
comparing, so reading it off the binary is awkward.

```c
printf("Input flag: ");
scanf("%s", input);
if (strlen(input) == 0x1b) { /* three nested loops mixing the characters, then compare */ }
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/cpctf_black_box/chall
```

```text
Input:
  stdin
  inferred length: 27

Goal:
  reaches 0x1013b3
  calls puts("Correct!")

Solver:
  backend: z3
  result: sat

Solution:
  CPCTF{ConS7RucT_A_fl46_b0X}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the loops have concrete bounds, so execution unrolls them and the comparison
  leaves one equation per character.

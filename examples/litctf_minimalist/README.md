# minimalist

| | |
|---|---|
| Origin | LIT CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/LexingtonInformaticsTournament/2022/rev/minimalist)) |
| Binary | `minimalist`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `LITCTF{Wh0_n33ds_a11_th0sE_f4ncy_1nstructions?}` |

## The challenge

The check is written with as few instruction kinds as possible: a chain of increments and
compares over 47 characters, one difference counted at a time.

```c
puts("Enter the flag: ");
for (i = 0; i < 0x2f; i++) /* fold the input into a counter */;
for (i = 0; i < 0x2f; i++) /* compare with the expected bytes */;
if (differences == 0) puts("The flag is correct."); else puts("Wrong flag!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/litctf_minimalist/minimalist
```

```text
Input:
  stdin
  inferred length: 47

Goal:
  reaches 0x1012ee
  calls puts("The flag is correct.")

Solver:
  backend: z3
  result: sat

Solution:
  LITCTF{Wh0_n33ds_a11_th0sE_f4ncy_1nstructions?}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the folding is linear, so each character ends up in its own equation.

# ctfd-plus

| | |
|---|---|
| Origin | LA CTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/LA/2023/rev/ctfd-plus)) |
| Binary | `ctfd_plus`, x86-64 PIE ELF, stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `lactf{m4yb3_th3r3_1s_s0m3_m3r1t_t0_us1ng_4_db}` |

## The challenge

Each flag character is compared with a value computed from a table by 32 rounds of
squaring, rotating, multiplying, and xoring:

```c
fgets(flag, 256, stdin);
flag[strcspn(flag, "\n")] = 0;
for (i = 0; i < 47; i++)
    if (decode(table[i]) != flag[i]) { puts("Incorrect flag."); return 0; }
puts("You got the flag! Unfortunately we don't exactly have a database to store the solve in...");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/lactf_ctfd_plus/ctfd_plus
```

```text
Input:
  stdin
  inferred length: 46

Goal:
  reaches 0x10112e
  calls puts("You got the flag! Unfortunately we don't exactly have a database to store the solve in...")

Solver:
  backend: z3
  result: sat

Solution:
  lactf{m4yb3_th3r3_1s_s0m3_m3r1t_t0_us1ng_4_db}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** `decode` only ever sees constants from the table, so symbolic execution just
  computes it: the scrambling never reaches the solver. What is left is 47 comparisons of
  one input byte with a constant.

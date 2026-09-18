# Fortune Teller

| | |
|---|---|
| Origin | CPCTF 2025, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/CPCTF/2025/rev/Fortune_Teller)) |
| Binary | `chall`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `CPCTF{y0u_c4n_s01v3_w1th0ut_r3Ad1nG_4ssembly}` |

## The challenge

A binary search tree of comparisons on a hash of the input picks which characters to xor
with what, spread over hundreds of branches. The name says it: you are meant to guess
rather than read it.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/cpctf_fortune_teller/chall
```

```text
Input:
  stdin
  inferred length: 45

Goal:
  reaches 0x40124f
  calls puts("Correct!\nYour today's lucky item is...  CO2 meter!")

Solver:
  backend: z3
  result: sat

Solution:
  CPCTF{y0u_c4n_s01v3_w1th0ut_r3Ad1nG_4ssembly}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the tree is decided by concrete values, so execution walks it without forking;
  the xors it performs become the equations for the answer.

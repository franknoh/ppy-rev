# addition

| | |
|---|---|
| Origin | LIT CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/LexingtonInformaticsTournament/2022/rev/addition)) |
| Binary | `addition`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `LITCTF{add1ti0n_is_h4rd}` |

## The challenge

```c
scanf("%s", input);
for (i = 0; i < 0x18; i++)
    if (input[i] + offsets[i] != expected[i]) { puts("wrong"); return 1; }
puts("correct");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/litctf_addition/addition
```

```text
Input:
  stdin
  inferred length: 24

Goal:
  reaches 0x1010e4
  calls puts("correct")

Solver:
  backend: z3
  result: sat

Solution:
  LITCTF{add1ti0n_is_h4rd}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** 24 characters, one addition and one comparison each.

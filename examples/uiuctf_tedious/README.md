# Tedious

| | |
|---|---|
| Origin | UIUCTF 2021, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/UIUCTF/2021/rev/Tedious)) |
| Binary | `challenge`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}` |

## The challenge

The flag goes through a long series of whole-buffer passes, each adding and xoring a
different pair of constants, before it is compared with a table:

```c
fgets(buffer, 40, stdin);
for (i = 0; i < 39; i++) buffer[i] = (buffer[i] + 0x3b) ^ 0x38;
for (i = 0; i < 39; i++) buffer[i] = (buffer[i] + 0x12) ^ 0xfd;
for (i = 0; i < 39; i++) buffer[i] = (buffer[i] + 4) ^ 0x50;
/* ... many more passes ... */
for (i = 0; i < 39; i++)
    if (buffer[i] != expected[i]) { printf("WRONG!"); return 0; }
printf("GOOD JOB!");
```

Tedious by hand; for a solver, one expression per byte.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/uiuctf_tedious/challenge
```

```text
Input:
  stdin
  inferred length: 38

Goal:
  reaches 0x1019d1
  calls printf("GOOD JOB!")

Solver:
  backend: z3
  result: sat

Solution:
  uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the transformation loops have concrete bounds, so they run without forking;
  each byte ends up as a nested add/xor expression over one input symbol.
- **Answer:** the 39 comparisons each constrain one byte, and Z3 inverts the whole chain
  of passes at once.

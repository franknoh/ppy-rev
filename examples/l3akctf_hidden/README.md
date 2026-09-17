# Hidden

| | |
|---|---|
| Origin | L3akCTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/L3akCTF/2024/rev/Hidden)) |
| Binary | `hidden`, x86-64 PIE ELF, not stripped |
| Input | `argv[1]` |
| Hints needed | none |
| Answer | `L3AK{b4by_sT3Ps}` |

## The challenge

The expected string is assembled at run time, so it is not visible in the binary:

```c
build(expected);                       /* writes the flag byte by byte */
if (argv[1] != NULL && strcmp(argv[1], expected) == 0) puts("Correct!");
else puts("Wrong!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/l3akctf_hidden/hidden
```

```text
Input:
  argv[1]
  inferred length: 16

Goal:
  reaches 0x10143e
  calls puts("Correct!")

Solver:
  backend: z3
  result: sat

Solution:
  L3AK{b4by_sT3Ps}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the builder runs on constants; the comparison then decides every byte.

# Sanity rev

| | |
|---|---|
| Origin | Hackappatoi CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/Hackappatoi/2022/rev/Sanity_rev)) |
| Binary | `sanityrev`, x86-64 PIE ELF, not stripped |
| Input | `argv[1]` |
| Hints needed | none |
| Answer | `hctf{It_h4s_b33N_345Y}` |

## The challenge

```c
if (argc == 2 && strcmp("hctf{It_h4s_b33N_345Y}", argv[1]) == 0)
    puts("You have found the flag!");
else
    puts("Not the right one :(");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/hackappatoi_sanity_rev/sanityrev
```

```text
Input:
  argv[1]
  inferred length: 22

Goal:
  reaches 0x1011b5
  calls puts("You have found the flag!")

Solver:
  backend: z3
  result: sat

Solution:
  hctf{It_h4s_b33N_345Y}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the flag is a string in the binary and the check is one comparison: the
  shortest possible example of the whole pipeline.

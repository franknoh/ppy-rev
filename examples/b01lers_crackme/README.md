# crackme

| | |
|---|---|
| Origin | b01lers CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/b01lers/2022/rev/crackme)) |
| Binary | `crackme`, x86-64 ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `bctf{133&_letmein_123}` |

## The challenge

One `if` per character, nested twenty-two deep:

```c
if (key[0] == 'b')
  if (key[1] == 'c')
    if (key[2] == 't')
      /* ... */
        puts("Correct!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/b01lers_crackme/crackme
```

```text
Input:
  stdin
  inferred length: 22

Goal:
  reaches 0x40143b
  calls printf("Key correct, activating.\n")

Solver:
  backend: z3
  result: sat

Solution:
  bctf{133&_letmein_123}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** each nesting level forks once and the failing side leaves the goal
  unreachable, so the search descends the chain in one pass.

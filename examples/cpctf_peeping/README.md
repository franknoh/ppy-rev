# peeping

| | |
|---|---|
| Origin | CPCTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/CPCTF/2024/rev/peeping)) |
| Binary | `chall`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `CPCTF{b3_4_cLa1rv0yANt}` |

## The challenge

```c
puts("Can you guess the flag?");
scanf("%s", input);
if (strcmp(input, flag) == 0) puts("Correct!"); else puts("Wrong...");
```

The flag lives in a global the program never prints.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/cpctf_peeping/chall
```

```text
Input:
  stdin
  inferred length: 23

Goal:
  reaches 0x101113
  calls puts("Correct!")

Solver:
  backend: z3
  result: sat

Solution:
  CPCTF{b3_4_cLa1rv0yANt}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** one comparison against data in the binary.

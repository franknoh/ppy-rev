# Intro to Reverse

| | |
|---|---|
| Origin | BlueHens CTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/BlueHens/2024/rev/Training_Problem_Intro_to_Reverse)) |
| Binary | `flagchecker`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `udctf{r3v3ng3_101}` |

## The challenge

Every character has its position subtracted before it is compared:

```c
fgets(input, 0x13, stdin);
for (i = 0; i <= 0x11; i++)
    if (input[i] - i != expected[i]) { puts("wrong"); return 1; }
puts("You got it!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/bluehens_intro_to_reverse/flagchecker
```

```text
Input:
  stdin
  inferred length: 18

Goal:
  reaches 0x10123c
  calls puts("You got it!")

Solver:
  backend: z3
  result: sat

Solution:
  udctf{r3v3ng3_101}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** 18 comparisons, each fixing one character.

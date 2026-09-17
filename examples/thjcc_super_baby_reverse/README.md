# Super baby reverse

| | |
|---|---|
| Origin | THJCC 2026, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/THJCC/2026/rev/Super_baby_reverse)) |
| Binary | `THJCC_Super_Baby_Reverse`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `THJCC{BaBY_r3v3rs3_f0r_beggin3r}` |

## The challenge

```c
printf("Enter the flag: ");
scanf("%254s", input);
if (strcmp(input, expected) == 0) puts("Correct"); else puts("Wrong");
```

`expected` is built on the stack one piece at a time, so `strings` does not show it.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/thjcc_super_baby_reverse/THJCC_Super_Baby_Reverse
```

```text
Input:
  stdin
  inferred length: 32

Goal:
  reaches 0x101213
  calls puts("Correct")

Solver:
  backend: z3
  result: sat

Solution:
  THJCC{BaBY_r3v3rs3_f0r_beggin3r}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** one comparison against bytes the program writes itself; symbolic execution
  computes them and Z3 reads the answer off the equalities.

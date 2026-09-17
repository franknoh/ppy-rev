# flag-checker

| | |
|---|---|
| Origin | WRECK CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/WRECKCTF/2022/rev/flag-checker)) |
| Binary | `chal`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `flag{gdb_1s_y0ur_b35t_fr13nd_6d94620fa6}` |

## The challenge

The flag is checked in three-character pieces, in a shuffled order, so that no single
comparison shows much:

```c
fgets(input, 0x29, stdin);
if (strlen(input) != 0x28) { puts("Wrong answer!"); return 1; }
if (strncmp(input + 24, "d94", 3) != 0) { puts("Wrong answer!"); return 1; }
if (strncmp(input + 4,  "db_", 3) != 0) { puts("Wrong answer!"); return 1; }
/* ... a dozen more pieces ... */
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/wreckctf_flag_checker/chal
```

```text
Input:
  stdin
  inferred length: 40

Goal:
  reaches 0x1014a9
  calls puts("Nice job! Submit your answer as the flag.")

Solver:
  backend: z3
  result: sat

Solution:
  flag{gdb_1s_y0ur_b35t_fr13nd_6d94620fa6}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** each `strncmp` pins three characters; the pieces cover the whole flag, and
  the length check fixes what is left.

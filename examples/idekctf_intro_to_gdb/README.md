# Intro to GDB

| | |
|---|---|
| Origin | idekCTF 2021, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/idekCTF/2021/rev/Intro_To_GDB)) |
| Binary | `Intro_to_GDB`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `idek{m0m_g3t_th3_c4m3rA!}` |

## The challenge

```c
puts("Hey, check out my new password checker! :D");
scanf("%s", input);
for (i = 0; i <= 0x19; i++)
    if (transform(input[i]) != expected[i]) { printf("Nope, that's not right..."); return 0; }
printf("GGs, you got it!");
```

The challenge wants you to step through it in gdb; solving reads the answer straight out.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/idekctf_intro_to_gdb/Intro_to_GDB
```

```text
Input:
  stdin
  inferred length: 25

Goal:
  reaches 0x10122e
  calls printf("GGs, you got it!")

Solver:
  backend: z3
  result: sat

Solution:
  idek{m0m_g3t_th3_c4m3rA!}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** 26 comparisons on one character each.

# traditions

| | |
|---|---|
| Origin | GDG Algiers CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/GDGAlgiers/2022/rev/traditions)) |
| Binary | `prog`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `CyberErudites{DA_Cl4$$IC_X0R_X_N07_Th4t_R4nd0m}` |

## The challenge

```c
printf("Enter the password : ");
fgets(input, 0x30, stdin);
if (strlen(input) != 0x2f) { printf("Wrong length"); return 1; }
for (i = 0; i < strlen(input); i++)
    if ((input[i] ^ key[i]) != expected[i]) { /* wrong */ }
puts("Correct, you can submit the flag");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/gdgalgiers_traditions/prog
```

```text
Input:
  stdin
  inferred length: 47

Goal:
  reaches 0x101438
  calls puts("Correct, you can submit the flag")

Solver:
  backend: z3
  result: sat

Solution:
  CyberErudites{DA_Cl4$$IC_X0R_X_N07_Th4t_R4nd0m}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the length check fixes 47 characters and each is decided by one xor.

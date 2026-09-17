# The Flag Vault

| | |
|---|---|
| Origin | KnightCTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/KnightCTF/2022/rev/The_Flag_Vault)) |
| Binary | `The_Flag_Vault`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `abracadabrahahaha` |

## The challenge

The vault password is a plain string on the stack; the flag is printed from a shuffled set
of characters once the password matches:

```c
strcpy(password, "abracadabrahahaha");   /* built with builtin_strncpy */
scanf("%s", input);
if (strcmp(password, input) == 0) {
    puts("\nCongratulations! Here is your flag:\n");
    printf("%s%s%s...", &c1, &c2, &c3 /* ... */);
}
```

The answer is the password; running the binary with it prints the flag.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/knightctf_flag_vault/The_Flag_Vault
```

```text
Input:
  stdin
  inferred length: 17

Goal:
  reaches 0x1012d4
  calls puts("\nCongratulations! Here is your flag:\n")

Solver:
  backend: z3
  result: sat

Solution:
  abracadabrahahaha

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Goal:** `"Congratulations! Here is your flag:"` is the most confident success message
  (`congrat`).
- **Search:** `strcmp` against a concrete string gives one byte equality per character.

# vault

| | |
|---|---|
| Origin | Digital Overdose CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/DigitalOverdose/2022/rev/vault)) |
| Binary | `vault`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `DOCTF{H4CK3RPR00F}` |

## The challenge

The password is the flag, held in pieces on the stack and compared with `strncmp`:

```c
printf("Enter the Password: ");
scanf("%s", input);
if (strncmp(password, input, 0x12) == 0) printf("Success! You've found the flag!\n%s\n", password);
else puts("Nope!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/digitaloverdose_vault/vault
```

```text
Input:
  stdin
  inferred length: 18

Goal:
  reaches 0x101334
  calls printf("Success! You've found the flag!\n%s\n")

Solver:
  backend: z3
  result: sat

Solution:
  DOCTF{H4CK3RPR00F}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** one comparison over 18 characters the program writes itself.

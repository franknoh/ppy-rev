# RevEng

| | |
|---|---|
| Origin | BYUCTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/BYUCTF/2023/rev/RevEng)) |
| Binary | `gettingBetter`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `She turned me into a newt` |

## The challenge

The passphrase is stored encrypted, with 5 added to every byte; the program decrypts it,
compares, and prints a flag decrypted the same way:

```c
fgets(input, 100, stdin);                    /* get_user_input, newline removed */
decrypt_passphrase(passphrase_encrypted, passphrase, 5);   /* subtracts 5 */
if (strcmp(input, passphrase) == 0) {
    decrypt_passphrase(flag_bytes, flag, 5);
    printf("Congratulations! The flag is %s\n", flag);
} else {
    puts("Incorrect passphrase. Please try again.");
}
```

The answer is the passphrase (a Monty Python line); the binary then prints the flag.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/byuctf_reveng/gettingBetter
```

```text
Input:
  stdin
  inferred length: 25

Goal:
  reaches 0x101368
  calls printf("Congratulations! The flag is %s\n")

Solver:
  backend: z3
  result: sat

Solution:
  She turned me into a newt

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** decrypting the stored passphrase is concrete computation; the comparison is
  between the input and known bytes.

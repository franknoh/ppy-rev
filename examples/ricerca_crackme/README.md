# crackme

| | |
|---|---|
| Origin | Ricerca CTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/Ricerca/2023/rev/crackme)) |
| Binary | `crackme`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `N1pp0n-Ich!_s3cuR3_p45$w0rD` |

## The challenge

```c
printf("Password: ");
if (scanf("%s", input) == 1 && strcmp(input, "N1pp0n-Ich!_s3cuR3_p45$w0rD") == 0)
    puts("[+] Authenticated");
else
    puts("[-] Permission denied");
```

The password is the answer; the flag is built from it.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/ricerca_crackme/crackme
```

```text
Input:
  stdin
  inferred length: 27

Goal:
  reaches 0x1015bd
  calls __printf_chk("The flag is \"%s\"\n")

Solver:
  backend: z3
  result: sat

Solution:
  N1pp0n-Ich!_s3cuR3_p45$w0rD

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** one comparison with a constant string, after the `%s` token is read.

# Scarface

| | |
|---|---|
| Origin | HeroCTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/HeroCTF/2023/rev/Scarface)) |
| Binary | `scarface`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `S4y_H3lL0_t0_mY_l1ttl3_FR13ND!!` |

## The challenge

The password is stored base64-encoded and reversed. The program decodes the stored string,
reverses it in place with the xor trick, and compares.

```c
decoded = base64_decode(stored);
reverse(decoded);            /* *a ^= *b; *b ^= *a; *a ^= *b; */
if (strcmp(input, decoded) == 0) printf("Well done! You can validate with ...");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/heroctf_scarface/scarface
```

```text
Input:
  stdin
  inferred length: 31

Goal:
  reaches 0x101659
  calls printf("Well done! You can validate with the flag Hero{%s}\n")

Solver:
  backend: z3
  result: sat

Solution:
  S4y_H3lL0_t0_mY_l1ttl3_FR13ND!!

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the decoding runs on constants, so the solver only sees the final comparison.
  The answer is the password; the challenge's flag is built from it.

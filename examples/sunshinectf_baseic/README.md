# BASEic

| | |
|---|---|
| Origin | SunshineCTF 2025, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/SunshineCTF/2025/rev/BASEic)) |
| Binary | `BASEic`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `sun{c0v3r1ng_ur_B4535}` |

## The challenge

The program base64-encodes what it reads and compares the start of the encoding with a
constant:

```c
printf("What is the flag> ");
scanf("%s", input);
if (strlen(input) == 0x16) {
    base64(input, encoded);
    if (strncmp(encoded, "c3Vue2MwdjNyMW5nX3V", 0x13) == 0) puts("[+] Correct!");
}
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/sunshinectf_baseic/BASEic
```

```text
Input:
  stdin
  inferred length: 22

Goal:
  reaches 0x1015c1
  calls puts("You got it, submit the flag!")

Solver:
  backend: z3
  result: sat

Solution:
  sun{c0v3r1ng_ur_B4535}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the encoder runs on the symbolic input, so each output character is an
  expression over three input bytes; Z3 inverts the base64 alphabet lookup directly.
- **Answer:** the length check fixes 22 characters, and the comparison decides them.

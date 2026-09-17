# Welcome

| | |
|---|---|
| Origin | n00bzCTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/n00bzCTF/2023/rev/Welcome)) |
| Binary | `chal`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `n00bz{N3v3R_$torE_$ENs1TIV3_1nFOrMa7IOn_P1aiNtexT_In_yoUr_bin4rI3S!!!!!}` |

## The challenge

The point of the challenge is that the flag is a plain string in the binary:

```c
printf("Input flag : ");
fgets(input, 256, stdin);
if (strcmp(input, "n00bz{...}") == 0) puts("Correct flag !"); else puts("Wrong flag !");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/n00bzctf_welcome/chal
```

```text
Input:
  stdin
  inferred length: 73

Goal:
  reaches 0x10124a
  calls puts("Correct flag !")

Solver:
  backend: z3
  result: sat

Solution:
  ASCII: n00bz{N3v3R_$torE_$ENs1TIV3_1nFOrMa7IOn_P1aiNtexT_In_yoUr_bin4rI3S!!!!!}\x00\n
  Hex:   6e 30 30 62 7a 7b 4e 33 76 33 52 5f 24 74 6f 72 45 5f 24 45 4e 73 31 54 49 56 33 5f 31 6e 46 4f 72 4d 61 37 49 4f 6e 5f 50 31 61 69 4e 74 65 78 54 5f 49 6e 5f 79 6f 55 72 5f 62 69 6e 34 72 49 33 53 21 21 21 21 21 7d 00 0a

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Answer:** `strcmp` stops at a NUL, so the line ppy-rev reports ends right after the
  flag: feed it without a trailing newline (`printf 'n00bz{...}' | ./chal`).
- **Search:** one comparison with a constant string.

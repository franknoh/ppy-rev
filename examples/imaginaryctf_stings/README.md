# Stings

| | |
|---|---|
| Origin | ImaginaryCTF 2021, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/ImaginaryCTF/2021/rev/Stings)) |
| Binary | `stings`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `ictf{str1ngs_4r3nt_h1dd3n_17b21a69}` |

## The challenge

After an ASCII-art bee, the program reads a password with `scanf` and compares every
character with a string built on the stack, shifted by one:

```c
scanf("%s", password);
for (i = 0; ; i++) {
    if (i > 34) { puts("Congrats! The password is the flag."); return 0; }
    if (password[i] != stored[i] - 1) { puts("I'm disappointed. *stings you*"); return -1; }
}
```

`strings` shows pieces of the shifted flag (`jdug|tus...`), which is the joke.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/imaginaryctf_stings/stings
```

```text
Input:
  stdin
  inferred length: 35

Goal:
  reaches 0x100895
  calls puts("Congrats! The password is the flag.")

Solver:
  backend: z3
  result: sat

Solution:
  ictf{str1ngs_4r3nt_h1dd3n_17b21a69}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Input:** `scanf("%s")` reads a whitespace-free token from stdin; the model forks on
  where the token ends, shortest first.
- **Search:** the stored string is concrete stack data written by `movabs` instructions, so
  each comparison is `password[i] == constant`; the 35 comparisons fix the answer byte by
  byte.

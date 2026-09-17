# Keycode

| | |
|---|---|
| Origin | ImaginaryCTF 2021, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/ImaginaryCTF/2021/rev/Keycode)) |
| Binary | `key`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `ictf{wh@t_g00d_i5_@_10ck_!f_th3_l0ck_!s_th3_k3y?}` |

## The challenge

The key is the checking function's own machine code:

```c
int checkFlag(char *flag) {
    for (i = 0; i <= 48; i++)
        if ((((unsigned char *)checkFlag)[i] ^ flag[i]) != flg[i]) return 0;
    return 1;
}
```

Patching `checkFlag` (a breakpoint, for instance) changes the key and breaks the check.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/imaginaryctf_keycode/key
```

```text
Input:
  stdin
  inferred length: 49

Goal:
  reaches 0x101209
  calls puts("You've found the flag!")

Solver:
  backend: z3
  result: sat

Solution:
  ictf{wh@t_g00d_i5_@_10ck_!f_th3_l0ck_!s_th3_k3y?}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Memory:** loads from the code of `checkFlag` read the program image, exactly the bytes
  the binary contains; nothing is patched because nothing runs natively.
- **Search:** 49 byte comparisons against `flg`, each inverted by Z3.

# Unbreakable Enterprise Product Activation

| | |
|---|---|
| Origin | Google CTF 2016, reversing ([binary via angr examples](https://github.com/angr/angr-doc/tree/master/examples/google2016_unbreakable_0)) |
| Binary | `unbreakable-enterprise-product-activation`, x86-64 ELF, stripped |
| Input | `argv[1]` |
| Hints needed | `--flag-format 'CTF{*}'` |
| Answer | `CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}` |

## The challenge

```text
$ ./unbreakable-enterprise-product-activation KEY
Product activation failure 255
```

`main` copies the key into a global buffer with `strncpy(buffer, argv[1], 0x43)` and then
calls about fifty small check functions. Each one relates one byte of the buffer to a few
others:

```c
if (buffer[0] != (buffer[0x1e] ^ buffer[0x26]) - buffer[8] + buffer[6])
    fail(0xff);   /* prints "Product activation failure %d" and exits */
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/google_unbreakable/unbreakable-enterprise-product-activation \
    --flag-format 'CTF{*}'
```

```text
Input:
  argv[1]
  inferred length: 51

Goal:
  reaches 0x400839
  calls puts("Thank you - product activated!")

Solver:
  backend: z3
  result: sat

Solution:
  CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}
```

About 14 seconds.

## Why the hint

Without it, `ppy-rev solve` answers with an **empty key**, and it is right. `strncpy` fills
the buffer with zeros, and every check is a sum or xor of bytes, so all of them hold for
zeros:

```text
Solution:
  (empty)

Verification:
  RevIR execution: passed (reaches the goal)
```

The binary accepts many keys; the flag is the one that looks like a flag. Google CTF flags
start with `CTF{` and end with `}`, and the shortest key of that shape is the flag (`solve`
prefers short answers; `--solutions 2` shows a longer one with junk before the final `}`).
`--prefix 'CTF{'` alone is enough too.

## How ppy-rev gets there

- **Main:** the binary is stripped; `main` is the function `_start` hands to
  `__libc_start_main`.
- **Goal:** `"Thank you - product activated!"` is success (`activated`), the
  `"Product activation failure %d"` format is failure.
- **Memory:** the key buffer is in a `.bss` section of 0x11 bytes, and `strncpy` writes
  0x43 bytes into it. The real program gets away with that because the loader maps whole
  pages; ppy-rev maps the rest of the page too, so the write is not mistaken for a crash.
- **Search:** each check has one feasible side, so there is a single path; Z3 solves the
  relations together with the flag format.

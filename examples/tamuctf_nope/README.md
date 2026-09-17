# nope

| | |
|---|---|
| Origin | TAMUctf 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/TAMUctf/2023/rev/nope)) |
| Binary | `nope`, x86-64 PIE ELF, not stripped |
| Input | `argv[1]` |
| Hints needed | none |
| Answer | `gigem{fUnky_1nlin3_4sm}` |

## The challenge

The flag is built on the stack and compared with a `strcmp` written in inline assembly
rather than the library one:

```c
build_key(key);                        /* writes the expected string byte by byte */
if (argc > 1 && strlen(argv[1]) == strlen(key) && strcmp(argv[1], key) == 0)
    puts("Congrats, you found the flag!");
else
    puts("nope.");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/tamuctf_nope/nope
```

```text
Input:
  argv[1]
  inferred length: 23

Goal:
  reaches 0x101396
  calls puts("Congrats, you found the flag!")

Solver:
  backend: z3
  result: sat

Solution:
  gigem{fUnky_1nlin3_4sm}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Semantics:** the hand-written `strcmp` is lifted from its instructions like any other
  code, so no model of the library function is needed.
- **Search:** the comparison loop ends at the first difference; each byte is decided once.

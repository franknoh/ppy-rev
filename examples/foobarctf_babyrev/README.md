# BabyRev

| | |
|---|---|
| Origin | FooBarCTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/FooBarCTF/2022/rev/BabyRev)) |
| Binary | `chall`, x86-64 PIE ELF, not stripped |
| Input | `argv[1]` |
| Hints needed | none |
| Answer | `GLUG{C01nc1d3nc3_c4n_b3_fr3aky_T6LSERDYB6}` |

## The challenge

The key has to be 42 characters, and one enormous condition relates them to each other and
to constants:

```c
if (argc == 2 && strlen(argv[1]) == 0x2a)
    if (key[3] == 'G' && (key[7] ^ key[11]) == 0x15 && /* dozens more */)
        puts(":) CORRECT!");
    else
        puts(";( INCORRECT");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/foobarctf_babyrev/chall
```

```text
Input:
  argv[1]
  inferred length: 42

Goal:
  reaches 0x102887
  calls puts(":) CORRECT!")

Solver:
  backend: z3
  result: sat

Solution:
  GLUG{C01nc1d3nc3_c4n_b3_fr3aky_T6LSERDYB6}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the whole check is one path; the conditions become one constraint system that
  Z3 solves in a single call.

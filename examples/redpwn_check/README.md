# check

| | |
|---|---|
| Origin | redpwn CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/redpwn/2022/rev/check)) |
| Binary | `challenge`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `hope{oops_all_flag_checkers_64961defe21b15e8}` |

## The challenge

The expected flag is decoded at run time with a key that changes as it goes, then compared:

```c
key = 0;
for (i = 0; i < 0x2d; i++) {
    expected[i] ^= (char) i;
    expected[i] ^= key;
    key += key * 2 ^ 0x54;
}
printf("what's the flag? ");
scanf("%s", input);
if (strcmp(input, expected) == 0) puts("correct!"); else puts("incorrect.");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/redpwn_check/challenge
```

```text
Input:
  stdin
  inferred length: 45

Goal:
  reaches 0x101940
  calls puts("correct!")

Solver:
  backend: z3
  result: sat

Solution:
  hope{oops_all_flag_checkers_64961defe21b15e8}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** decoding runs on concrete data, so the solver only sees the final comparison
  with 45 known bytes.

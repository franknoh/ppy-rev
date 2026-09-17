# keygen

| | |
|---|---|
| Origin | HSCTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/HSCTF/2023/rev/keygen)) |
| Binary | `keygen`, x86-64 PIE ELF, not stripped |
| Input | `argv[1]` |
| Hints needed | none |
| Answer | `flag{6275745f-7768-6174-5f6c-6f636b3f0000}` |

## The challenge

```c
if (argc == 2 && strlen(argv[1]) == 42) {
    for (key = argv[1], table = expected; ; key++, table++) {
        if (*key == 0) { puts("Correct"); return 0; }
        if ((*key ^ 10) != *table) break;
    }
}
puts("Wrong");
return 1;
```

The key is the flag, xored with 10 into the table (its hex groups spell
`but_what_lock?`).

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/hsctf_keygen/keygen
```

```text
Input:
  argv[1]
  inferred length: 42

Goal:
  reaches 0x101201
  calls puts("Correct")

Solver:
  backend: z3
  result: sat

Solution:
  flag{6275745f-7768-6174-5f6c-6f636b3f0000}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Input:** the length check makes the answer exactly 42 bytes.
- **Search:** the loop runs until the key's terminator; with the length known, 42
  comparisons decide every byte.

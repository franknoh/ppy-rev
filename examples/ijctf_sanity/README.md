# Sanity

| | |
|---|---|
| Origin | IJCTF 2021, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/IJCTF/2021/rev/Sanity)) |
| Binary | `sanity`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `IJCTF{you_did_not_fall_for_it_right?}` |

## The challenge

The flag is xored with a key at startup, and the result is what the input is compared with:

```c
for (i = 0; i < strlen(flag); i++) expected[i] = key[i] ^ flag[i];
puts("Whats the flag?");
scanf("%s", input);
if (strcmp(input, expected) == 0) puts("Correct!"); else puts("Wrong!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/ijctf_sanity/sanity
```

```text
Input:
  stdin
  inferred length: 37

Goal:
  reaches 0x101285
  calls puts("Correct!")

Solver:
  backend: z3
  result: sat

Solution:
  IJCTF{you_did_not_fall_for_it_right?}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the xor runs on constants, so the comparison is against bytes execution
  already knows.

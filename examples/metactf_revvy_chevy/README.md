# Revvy Chevy

| | |
|---|---|
| Origin | MetaCTF 2021, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/MetaCTF/2021/rev/Revvy_Chevy)) |
| Binary | `chall`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `MetaCTF{pr0p3r_encrypt10n_1snt_s0_e4sy...}` |

## The challenge

The input is xored with a key that changes along the buffer, then compared:

```c
printf("What's the flag? ");
fgets(input, 0x40, stdin);
for (i = 0; i < 0x40; i++) input[i] ^= key + i;
if (memcmp(input, expected, 0x40) == 0) puts("You got it!"); else puts("That's not it...");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/metactf_revvy_chevy/chall
```

```text
Input:
  stdin
  inferred length: 42

Goal:
  reaches 0x101326
  calls puts("You got it!")

Solver:
  backend: z3
  result: sat

Solution:
  MetaCTF{pr0p3r_encrypt10n_1snt_s0_e4sy...}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** one xor per byte with a position-dependent constant, then a comparison with
  data in the binary.

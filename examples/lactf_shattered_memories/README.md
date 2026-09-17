# shattered-memories

| | |
|---|---|
| Origin | LA CTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/LA/2024/rev/shattered_memories)) |
| Binary | `shattered-memories`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `lactf{not_what_forgive_and_forget_means}` |

## The challenge

The flag is checked in five 8-byte pieces, in shuffled order, and the number of matching
pieces picks the message:

```c
fgets(input, 128, stdin);
input[strcspn(input, "\n")] = 0;
if (strlen(input) != 40) { puts("No, I definitely remember it being a different length..."); return 0; }
matches += strncmp(input + 8,  "t_what_f", 8) == 0;
matches += strncmp(input + 32, "t_means}", 8) == 0;
matches += strncmp(input + 24, "nd_forge", 8) == 0;
matches += strncmp(input,      "lactf{no", 8) == 0;
matches += strncmp(input + 16, "orgive_a", 8) == 0;
switch (matches) { /* 5: "Yes! That's it! That's the flag! I remember now!" */ }
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/lactf_shattered_memories/shattered-memories
```

```text
Input:
  stdin
  inferred length: 40

Goal:
  reaches 0x1013a3
  calls puts("Yes! That's it! That's the flag! I remember now!")

Solver:
  backend: z3
  result: sat

Solution:
  lactf{not_what_forgive_and_forget_means}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Goal:** of the six possible messages, only `"Yes! That's it! ..."` is success; the
  others ("isn't it", "not quite") are failures.
- **Search:** the count of matches is a sum of comparison results, so only the path with
  all five pieces matching reaches the goal.

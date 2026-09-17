# unoriginal

| | |
|---|---|
| Origin | ImaginaryCTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/ImaginaryCTF/2024/rev/unoriginal)) |
| Binary | `unoriginal`, x86-64 PIE ELF, not stripped |
| Input | stdin (`gets`) |
| Hints needed | none |
| Answer | `ictf{just_another_flag_checker_a3465d5e5ee234ba}` |

## The challenge

```c
printf("Enter your flag here: ");
gets(input);
for (i = 0; i < 48; i++) input[i] ^= 5;
if (strcmp(input, "lfqc~opvqZdkjqm`wZcidbZfm`fn`wZd6130a0`0``761gdx") == 0)
    puts("Correct!");
else
    puts("Incorrect.");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/imaginaryctf_unoriginal/unoriginal
```

```text
Input:
  stdin
  inferred length: 48

Goal:
  reaches 0x101258
  calls puts("Correct!")

Solver:
  backend: z3
  result: sat

Solution:
  ictf{just_another_flag_checker_a3465d5e5ee234ba}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Input:** `gets` reads a line of any length; the model writes it into the stack buffer
  and ends it where the newline is.
- **Search:** one xor per byte and a `strcmp` with a constant.

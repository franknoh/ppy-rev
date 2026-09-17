# Guess the Flag

| | |
|---|---|
| Origin | ångstromCTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/angstromCTF/2024/rev/Guess_the_Flag)) |
| Binary | `guess_the_flag`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `actf{committed_to_the_least_significant_bit}` |

## The challenge

```c
puts("Go ahead, guess the flag: ");
fgets(input, 0x3f, stdin);
for (p = input; p < input + strlen(input); p++) *p ^= 1;
if (strcmp(input, secretcode) == 0) puts("Correct! It was kinda obvious tbh.");
else puts("Wrong. Not sure why you'd think it'd be that.");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/angstrom_guess_the_flag/guess_the_flag
```

```text
Input:
  stdin
  inferred length: 45

Goal:
  reaches 0x101160
  calls puts("Correct! It was kinda obvious tbh.")

Solver:
  backend: z3
  result: sat

Solution:
  ASCII: actf{committed_to_the_least_significant_bit}\x00\n
  Hex:   61 63 74 66 7b 63 6f 6d 6d 69 74 74 65 64 5f 74 6f 5f 74 68 65 5f 6c 65 61 73 74 5f 73 69 67 6e 69 66 69 63 61 6e 74 5f 62 69 74 7d 00 0a

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Answer:** the flag, with the terminator the comparison needs. `strcmp` stops at a NUL,
  so the answer ppy-rev reports ends the line right there: feed the flag without a trailing
  newline (`printf 'actf{...}' | ./guess_the_flag`).
- **Search:** one xor per byte and a comparison with a string in the binary.

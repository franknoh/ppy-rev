# Beginner Rev

| | |
|---|---|
| Origin | SwampCTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/SwampCTF/2024/rev/Beginner_Rev)) |
| Binary | `BeginnerREV`, x86-64 ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `swampCTF{X0R_inv0luti0n_i5_c00l}` |

## The challenge

```c
printf("Please enter the flag:");
scanf("%s", input);
if (strlen(input) == 32)
    while (input[i] == (encoded[i] ^ 0x41)) {
        if (i == 32) { puts("Congratulations! You found the flag!"); return 0; }
        i++;
    }
puts("The flag entered is incorrect!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/swampctf_beginner_rev/BeginnerREV
```

```text
Input:
  stdin
  inferred length: 32

Goal:
  reaches 0x4011ce
  calls puts("Congratulations! You found the flag!")

Solver:
  backend: z3
  result: sat

Solution:
  swampCTF{X0R_inv0luti0n_i5_c00l}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** one xor per byte against data in the binary; the length check fixes the
  answer at 32 characters.

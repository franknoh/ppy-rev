# angry

| | |
|---|---|
| Origin | BuckeyeCTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/BuckeyeCTF/2022/rev/angry)) |
| Binary | `angry`, x86-64 PIE ELF, stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `buckeye{st!ll_b3tt3r_th4n_strfry}` |

## The challenge

The input is "frobnicated" in place: every byte is rotated left by the previous
(already rotated) byte, starting from 42, and the result must equal a stored string.

```c
fgets(input, 99, stdin);
input[strcspn(input, "\n")] = 0;
char key = 42;
for (i = 0; i < strlen(input); i++) {
    input[i] = rotate_left(input[i], key % 8);
    key = input[i];
}
if (strlen(input) == strlen(target) && strcmp(input, target) == 0)
    puts("Congratulations, you found the special string to frob.");
else
    puts("Failure, you didn't send an interesting string.");
```

The name hints at angr; ppy-rev does the same job.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/buckeyectf_angry/angry
```

```text
Input:
  stdin
  inferred length: 33

Goal:
  reaches 0x1013c1
  calls puts("Congratulations, you found the special string to frob.")

Solver:
  backend: z3
  result: sat

Solution:
  buckeye{st!ll_b3tt3r_th4n_strfry}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Slicing:** before reading input the program prints `"The special number today is...
  %d"`. Nothing depends on that output, so the call and the value it prints are skipped.
- **Search:** the rotation amount of each byte depends on the previous result, so the
  bytes are chained; `strlen` and `strcmp` over the frobbed buffer turn into comparisons
  Z3 solves together.

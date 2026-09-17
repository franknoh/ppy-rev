# verybabyrev

| | |
|---|---|
| Origin | RaRCTF 2021, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/RaRCTF/2021/rev/verybabyrev)) |
| Binary | `verybabyrev`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `rarctf{3v3ry_s1ngl3_b4by-r3v_ch4ll3ng3_u535_x0r-f0r_s0m3_r34s0n_4nd_1-d0nt_kn0w_why_dc37158365}` |

## The challenge

Each character is xored with the next one, from the front, and the result is compared with
a stored buffer:

```c
printf("Enter your flag: ");
fgets(input, 0x80, stdin);
if (input[0] != 'r') { puts("Nope!"); return 1; }
for (i = 0; i < 0x7f; i++) input[i] ^= input[i + 1];
if (memcmp(input, expected, ...) == 0) puts("Correct!"); else puts("Nope!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/rarctf_verybabyrev/verybabyrev
```

```text
Input:
  stdin
  inferred length: 95

Goal:
  reaches 0x101332
  calls puts("Correct!")

Solver:
  backend: z3
  result: sat

Solution:
  rarctf{3v3ry_s1ngl3_b4by-r3v_ch4ll3ng3_u535_x0r-f0r_s0m3_r34s0n_4nd_1-d0nt_kn0w_why_dc37158365}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the chain ties each character to the next, so the solver works backwards from
  the stored buffer; the first character is given away by the check before the loop.

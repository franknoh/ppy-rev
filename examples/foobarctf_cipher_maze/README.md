# Cipher Maze

| | |
|---|---|
| Origin | FooBarCTF 2025, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/FooBarCTF/2025/rev/Cipher_Maze)) |
| Binary | `chall`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `x0r_and_l0g1c@l_sh1ft_e@sy_r1gh8??` |

## The challenge

Each character is xored with a value the program computes, and the 34 results have to match
a table:

```c
printf("ENTER THE FLAG : ");
scanf("%s", input);
for (i = 0; i < 0x22; i++) mixed[i] = input[i] ^ key;
for (i = 0; i <= 0x21; i++)
    if (mixed[i] != expected[i]) { /* wrong */ }
printf("YAY U MADE IT \n...");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/foobarctf_cipher_maze/chall
```

```text
Input:
  stdin
  inferred length: 34

Goal:
  reaches 0x10141d
  calls printf("YAY U MADE IT \n%c%c%c%c{%s}\n")

Solver:
  backend: z3
  result: sat

Solution:
  x0r_and_l0g1c@l_sh1ft_e@sy_r1gh8??

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the xor and the comparison give one equation per character; the answer is the
  password the challenge asks for.

# baby rev

| | |
|---|---|
| Origin | IrisCTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/IrisCTF/2023/rev/baby_rev)) |
| Binary | `baby_baby_rev`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `irisctf{microsoft_word_at_home:}` |

## The challenge

A registration code for "SuperTexEdit": each character has its own constant subtracted,
and what is left has to equal the character's position.

```c
scanf("%s", code);
if (strlen(code) == 32) {
    code[0] += -0x69; code[1] += -0x71; code[2] += -0x67;  /* ... one per character ... */
    for (i = 0; i <= 31; i++)
        if (i != code[i]) { puts("Invalid code!"); return 1; }
    puts("Key Valid!");
}
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/irisctf_baby_rev/baby_baby_rev
```

```text
Input:
  stdin
  inferred length: 32

Goal:
  reaches 0x1015a5
  calls puts("Key Valid!")

Solver:
  backend: z3
  result: sat

Solution:
  irisctf{microsoft_word_at_home:}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** each character is decided by one subtraction and one comparison, so the
  answer follows from 32 independent equations.

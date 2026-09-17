# One Bite

| | |
|---|---|
| Origin | ångstromCTF 2019, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/angstromCTF/2019/rev/One_Bite)) |
| Binary | `one_bite`, x86-64 ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `actf{i_think_im_going_to_be_sick}` |

## The challenge

```c
puts("Give me a flag to eat: ");
fgets(input, 0x22, stdin);
for (i = 0; i < strlen(input); i++) input[i] ^= 0x3c;
if (strcmp(input, "]_HZGUcHTURWcUQc[SUR[cHSc^YcOU_WA") == 0)
    puts("Yum, that was a tasty flag.");
else
    puts("That didn't taste so good :(");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/angstrom_one_bite/one_bite
```

```text
Input:
  stdin
  inferred length: 33

Goal:
  reaches 0x400747
  calls puts("Yum, that was a tasty flag.")

Solver:
  backend: z3
  result: sat

Solution:
  actf{i_think_im_going_to_be_sick}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** one xor per byte, then a comparison with a string in the binary.

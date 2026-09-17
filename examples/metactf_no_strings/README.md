# There Are No Strings on Me

| | |
|---|---|
| Origin | MetaCTF 2021, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/MetaCTF/2021/rev/There_Are_No_Strings_on_Me)) |
| Binary | `strings`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `MetaCTF{this_is_the_most_secure_ever}` |

## The challenge

The password is assembled on the stack so that `strings` does not show it, and it is also
the flag:

```c
printf("Input the password: ");
fgets(input, 256, stdin);
if (strcmp(input, password) == 0) printf("Yay! Here's your flag: %s\n", password);
else puts("Begone!!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/metactf_no_strings/strings
```

```text
Input:
  stdin
  inferred length: 37

Goal:
  reaches 0x1011e1
  calls printf("Yay! Here's your flag: %s\n")

Solver:
  backend: z3
  result: sat

Solution:
  MetaCTF{this_is_the_most_secure_ever}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the password is written byte by byte by the program, so execution knows it;
  the comparison then pins the answer.

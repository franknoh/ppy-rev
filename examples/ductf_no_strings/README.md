# no strings

| | |
|---|---|
| Origin | DownUnderCTF 2021, rev (beginner) ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/DownUnderCTF/2021/rev/no_strings)) |
| Binary | `nostrings`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | `--flag-format 'DUCTF{*}' --charset printable` |
| Answer | `DUCTF{stringent_strings_string}` |

## The challenge

The flag is stored as a wide string, one byte of text and one zero byte per character, so
plain `strings` does not show it (`strings -el` does):

```c
printf("flag? ");
fgets(input, 70, stdin);
for (i = 0; i < strlen(input) - 1; i++)
    if (input[i] != flag[2 * i]) { puts("wrong!"); return -1; }
puts("correct!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/ductf_no_strings/nostrings --flag-format 'DUCTF{*}' --charset printable
```

```text
Input:
  stdin
  inferred length: 31

Goal:
  reaches 0x101227
  calls puts("correct!")

Solver:
  backend: z3
  result: sat

Solution:
  DUCTF{stringent_strings_string}

Verification:
  RevIR execution: passed (reaches the goal)
```

## Why the hint

The loop only checks as many characters as the input has, so an empty line passes: that is
the first answer `solve` finds without hints. A flag format asks for `DUCTF{...}`, but a
NUL byte right after the prefix would still end the check early, so printable characters
are required too. With both, the only input left is the whole flag.

## How ppy-rev gets there

- **Search:** each loop iteration compares one input byte with a flag byte; `strlen` of the
  input decides how many iterations run.

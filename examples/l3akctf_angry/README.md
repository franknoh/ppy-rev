# Angry

| | |
|---|---|
| Origin | L3akCTF 2024, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/L3akCTF/2024/rev/Angry)) |
| Binary | `angry_patched_skill_issues`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | `--flag-format 'L3AK{*}'` |
| Answer | `L3AK{angr_4_l@f3_d0nt_do_i@_m4nU4lly}` |

## The challenge

The challenge is named after angr, and it is one long condition: some characters are given
outright, the rest only through xors and comparisons between positions.

```c
fgets(input, ..., stdin);
if (input[8] == 'r' && input[9] == '_' &&
    (input[2] ^ input[13] ^ input[0] ^ input[1]) == ... &&
    (input[17] ^ input[21]) == 0x3b && /* dozens more */)
    puts("Correct!");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/l3akctf_angry/angry_patched_skill_issues --flag-format 'L3AK{*}'
```

```text
Input:
  stdin
  inferred length: 37

Goal:
  reaches 0x101826
  calls puts("Congratulations !")

Solver:
  backend: z3
  result: sat

Solution:
  L3AK{angr_4_l@f3_d0nt_do_i@_m4nU4lly}

Verification:
  RevIR execution: passed (reaches the goal)
```

## Why the hint, and the two free characters

The relations do not pin every character: without a hint `solve` answers with a string that
passes the check but is not the flag. The flag shape fills in most of what the conditions
leave open — all but positions 13 and 26, where any of several characters satisfies the
xors. The solver picks `@` at both, which is the string the authors meant, and the original
binary accepts it: `--verify` prints `native (sandboxed): passed (exit status 0, prints
"Congratulations !")`.

## How ppy-rev gets there

- **Search:** one path, one constraint system; Z3 solves the relations between positions
  together with the characters that are pinned outright.

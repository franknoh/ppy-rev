# High Quality Checks

| | |
|---|---|
| Origin | ångstromCTF 2019, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/angstromCTF/2019/rev/High_Quality_Checks)) |
| Binary | `high_quality_checks`, x86-64 ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `actf{fun_func710n5}` |

## The challenge

A classic solver challenge: the input has to satisfy a list of small predicates, each a
function of its own.

```c
scanf("%s", input);
if (strlen(input) < 0x13) { puts("Flag is too short."); return 0; }
if (t(input) && v(input[0]) && u(input[16], input[17]) && w(input + 1) &&
    b(input, 0x12) && b(input, 4) && z(input, 0x6c) && s(input))
    puts("You found the flag!");
else
    puts("That's not the flag.");
```

The predicates check sums, products, and relations between characters rather than their
values, so there is nothing to read off the binary.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/angstrom_high_quality_checks/high_quality_checks
```

```text
Input:
  stdin
  inferred length: 19

Goal:
  reaches 0x400ad2
  calls puts("You found the flag!")

Solver:
  backend: z3
  result: sat

Solution:
  actf{fun_func710n5}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Goal:** `"You found the flag!"`; `"Flag is too short."` mentions the flag but is a
  complaint about length, so it is ranked as a failure, not the goal.
- **Search:** the predicates are all on one path, and Z3 solves their conjunction in one
  go — the same thing solutions to this challenge do by hand with a solver script.

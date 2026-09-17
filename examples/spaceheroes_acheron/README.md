# Acheron

| | |
|---|---|
| Origin | Space Heroes 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/SpaceHeroes/2023/rev/Acheron)) |
| Binary | `Acheron`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `NENWSSEWSNENSSWEENWSNNESS` |

## The challenge

An escape-the-planet story: the input is a route, one letter per step, and the program
checks it move by move.

```c
fgets(route, 0x1a, stdin);
if (route[0] == 'N')
  if (route[1] == 'E')
    if (route[2] == 'N')
      /* ... 25 moves ... */
        puts("You made it back to your ship successfully, ...");
```

The answer is the route; running the binary with it prints the flag.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/spaceheroes_acheron/Acheron
```

```text
Input:
  stdin
  inferred length: 25

Goal:
  reaches 0x101194
  calls puts("You made it back to your ship successfully, you feel a weird sensation in your chest however... ")

Solver:
  backend: z3
  result: sat

Solution:
  NENWSSEWSNENSSWEENWSNNESS

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** each move forks once, and a wrong move ends the story, so the 25 comparisons
  are decided in order.

# string-cheese

| | |
|---|---|
| Origin | LA CTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/LA/2023/rev/string-cheese)) |
| Binary | `string_cheese`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `blueberry` |

## The challenge

```c
printf("What's my favorite flavor of string cheese? ");
fgets(input, 256, stdin);
input[strcspn(input, "\n")] = 0;
if (strcmp(input, "blueberry") == 0) {
    puts("...how did you know? That isn't even a real flavor...");
    puts("Well I guess I should give you the flag now...");
    print_flag();   /* reads flag.txt */
} else {
    puts("Hmm... I don't think that's quite it. Better luck next time!");
}
```

The flavor is right there in `strings`; the real flag is only in `flag.txt` on the server.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/lactf_string_cheese/string_cheese
```

```text
Input:
  stdin
  inferred length: 9

Goal:
  reaches 0x101299
  calls puts("...how did you know? That isn't even a real flavor...")

Solver:
  backend: z3
  result: sat

Solution:
  blueberry

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Input:** `fgets` reads the line and `strcspn` cuts it at the newline; `--output` writes
  the answer as the program reads it, `blueberry` and a newline.
- **Goal:** `"...how did you know?"` is success (`how did you`); the `"not quite it"`
  message is failure.

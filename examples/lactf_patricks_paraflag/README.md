# patricks-paraflag

| | |
|---|---|
| Origin | LA CTF 2025, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/LA/2025/rev/patricks_paraflag)) |
| Binary | `patricks-paraflag`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `lactf{the_flag_got_lost_in_infinity}` |

## The challenge

The input's first and second halves are interleaved and compared with a stored string:

```c
fgets(input, 256, stdin);
n = strcspn(input, "\n");
input[n] = 0;
if (strlen(target) != n) { puts("Bad length >:("); return 1; }
for (i = 0; i < n / 2; i++) {
    mixed[2 * i] = input[i];
    mixed[2 * i + 1] = input[i + n / 2];
}
mixed[n] = 0;
printf("Paradoxified: %s\n", mixed);
if (strcmp(target, mixed) == 0) puts("That's the flag! :D");
else puts("You got the flag wrong >:(");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/lactf_patricks_paraflag/patricks-paraflag
```

```text
Input:
  stdin
  inferred length: 36

Goal:
  reaches 0x1012a4
  calls puts("That's the flag! :D")

Solver:
  backend: z3
  result: sat

Solution:
  lactf{the_flag_got_lost_in_infinity}

Verification:
  RevIR execution: failed (stopped: printf: read of 1 byte(s) at 0xfffeddf0 faults (function main, block 4, at 0x101254))
```

## How ppy-rev gets there

- **Input:** the length check fixes the line length to that of `target`, which the binary
  stores as a string.
- **Slicing:** the `"Paradoxified: %s"` printout cannot affect the verdict and is skipped.
- **Search:** `strcmp` over the interleaved buffer compares each position with one input
  byte; the solver puts every byte back where it came from.

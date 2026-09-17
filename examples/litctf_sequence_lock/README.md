# The Sequence Lock

| | |
|---|---|
| Origin | LIT CTF 2026, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/LexingtonInformaticsTournament/2026/rev/sequence_lock)) |
| Binary | `seqlock`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `LITCTF{f1bon4cci_ch41ns_ftw}` |

## The challenge

A vault that mixes the flag with a Fibonacci sequence before comparing:

```c
puts("== The Sequence Lock ==");
printf("flag> ");
fgets(input, 0x100, stdin);
/* fold each character with the running Fibonacci value, then compare */
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/litctf_sequence_lock/seqlock
```

```text
Input:
  argv[1]
  inferred length: 28
  stdin
  inferred length: 0

Goal:
  reaches 0x10142b
  calls puts("Correct flag!")

Solver:
  backend: z3
  result: sat

Solution:
  LITCTF{f1bon4cci_ch41ns_ftw}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the sequence is concrete, so the fold leaves one equation per character;
  the length check narrows the rest.

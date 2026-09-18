# Secret Key

| | |
|---|---|
| Origin | CPCTF 2025, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/CPCTF/2025/rev/Secret_Key)) |
| Binary | `chall`, x86-64 PIE ELF, not stripped |
| Input | stdin (`scanf`) |
| Hints needed | none |
| Answer | `reversing` |

## The challenge

The key unlocks a routine that decodes and prints the flag; even characters and odd ones go
through different arithmetic:

```c
scanf("%s", key);
if (correct(key)) printflag();      /* (c ^ (i + 0x12) ^ i) - i) / 3 and friends */
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/cpctf_secret_key/chall
```

```text
Input:
  stdin
  inferred length: 9

Goal:
  reaches 0x101488
  calls puts("Congraturations!")

Solver:
  backend: z3
  result: sat

Solution:
  reversing

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Answer:** the key, `reversing`; running the binary with it prints the flag.

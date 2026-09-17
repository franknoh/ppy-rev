# Link Start

| | |
|---|---|
| Origin | TSCCTF 2025, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/TSCCTF/2025/rev/Link_Start)) |
| Binary | `chal`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `TSC{Y0u_4Re_a_L1nK3d_LI5t_MasTeR_@ka_LLM~~~}` |

## The challenge

The flag is stored in a linked list built with `malloc`, walked backwards, and compared
four characters at a time after an xor that depends on the position:

```c
fgets(input, 100, stdin);
if (strlen(input) == 0x2c) {
    /* walk the list from its end, xor each group of four with 0x10 * (i + 1) */
    for (i = 0; i < 4; i++) group[i] = byte ^ ((i + 1) * 0x10);
    /* ... compare with the list's nodes ... */
}
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/tscctf_link_start/chal
```

```text
Input:
  stdin
  inferred length: 44

Goal:
  reaches 0x101773
  calls puts("Logout Success :)")

Solver:
  backend: z3
  result: sat

Solution:
  TSC{Y0u_4Re_a_L1nK3d_LI5t_MasTeR_@ka_LLM~~~}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Memory:** `malloc` hands out addresses from a modeled heap, so the list and its nodes
  are ordinary memory the executor follows.
- **Search:** the walk is concrete; the xors leave one equation per character.

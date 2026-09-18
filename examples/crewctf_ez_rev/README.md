# ez rev

| | |
|---|---|
| Origin | CrewCTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/CrewCTF/2023/rev/ez_rev)) |
| Binary | `a.out`, x86-64 ELF, statically linked |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `flag{ez_rev_goes_brrrrr....but_wait_a_seccond_the_format_flag_looks_weird}` |

## The challenge

```c
puts("[+] Another flag checker...");
fgets(input, 0x100, stdin);
for (i = 0; i < 0x4a; i++)
    if (input[i] != (expected[i] ^ 0x70)) { puts("[-] No :("); return 1; }
puts("[+] Correct!!");
```

The binary is statically linked, so the lifted program includes the C library's own code.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/crewctf_ez_rev/a.out
```

```text
Input:
  stdin
  inferred length: 74

Goal:
  reaches 0x401211
  calls puts("[+] Correct!!")

Solver:
  backend: z3
  result: sat

Solution:
  flag{ez_rev_goes_brrrrr....but_wait_a_seccond_the_format_flag_looks_weird}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** 74 characters, one xor each. Static linking makes the module much larger, but
  only the code the input reaches matters: the slice keeps the checking loop.

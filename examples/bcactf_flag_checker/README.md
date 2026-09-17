# My Very Flag Checker

| | |
|---|---|
| Origin | BCACTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/BCACTF/2022/rev/My_Very_Flag_Checker)) |
| Binary | `whatisflag`, x86-64 ELF, not stripped |
| Input | `argv[1]` |
| Hints needed | none |
| Answer | `bcactf{fl4G_Und3rL00keD_e7df9c}` |

## The challenge

```text
$ ./whatisflag guess
Welcome to my flag checker :)
Incorrect flag.
```

```c
if (strlen(flag) != 31) { puts("Incorrect flag."); return 1; }
for (i = 0; i < 31; i++)
    if ((raw2[i] ^ flag[i]) != raw1[i]) { puts("Incorrect flag"); return 1; }
puts("Correct! That is the correct flag");
```

`raw1` and `raw2` are pointers to two byte arrays in the binary.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/bcactf_flag_checker/whatisflag
```

```text
Input:
  argv[1]
  inferred length: 31

Goal:
  reaches 0x4011b9
  calls puts("Correct! That is the correct flag")

Solver:
  backend: z3
  result: sat

Solution:
  bcactf{fl4G_Und3rL00keD_e7df9c}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Input:** `argv[1]` flows into `strlen` and into the comparison loop.
- **Goal:** `"Correct! That is the correct flag"`; both `"Incorrect flag"` messages are avoided.
- **Search:** each byte forks once; the wrong side leads to a failure message and is
  dropped, and Z3 undoes the xor with the constant bytes loaded through `raw1` and `raw2`.

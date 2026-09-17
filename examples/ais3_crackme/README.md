# ais3_crackme

| | |
|---|---|
| Origin | AIS3 summer school crackme by Tyler Nighswander, distributed with the [angr examples](https://github.com/angr/angr-doc/tree/master/examples/ais3_crackme) |
| Binary | `ais3_crackme`, x86-64 ELF, not stripped |
| Input | `argv[1]` |
| Hints needed | none |
| Answer | `ais3{I_tak3_g00d_n0t3s}` |

## The challenge

```text
$ ./ais3_crackme KEY
I'm sorry, that's the wrong secret key!
```

`main` passes `argv[1]` to `verify`, which transforms each byte and compares it with a
23-byte table in `.data`:

```c
for (i = 0; key[i]; i++) {
    uint8_t b = key[i] ^ i;
    b = rotate_left(b, (i ^ 9) & 3) + 8;
    if (b != encrypted[i]) return 0;
}
return i == 23;
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/ais3_crackme/ais3_crackme
```

```text
Input:
  argv[1]
  inferred length: 23

Goal:
  reaches 0x400607
  calls puts("Correct! that is the secret key!")

Solver:
  backend: z3
  result: sat

Solution:
  ais3{I_tak3_g00d_n0t3s}

Verification:
  RevIR execution: passed (reaches the goal)
```

About 7 seconds, most of it Ghidra's first analysis (later runs use the cache).

## How ppy-rev gets there

- **Input:** `argv[1]` flows into `strlen` and into `verify`, so it is the input.
- **Goal:** `"Correct! that is the secret key!"` is the success message and
  `"I'm sorry, ..."` the one to avoid.
- **Search:** every loop iteration forks on one comparison; paths that fail a comparison
  can no longer reach the goal and are dropped at once, so the search walks straight down
  the 23 bytes.
- **Answer:** Z3 inverts the rotate/xor/add for each byte. The answer is then re-run on
  the lifted program before it is printed.

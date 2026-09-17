# crackme 2

| | |
|---|---|
| Origin | b01lers CTF 2022, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/b01lers/2022/rev/crackme_2)) |
| Binary | `crackme_2`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `bctf{4lg3br4!}` |

## The challenge

Like the first crackme, but some characters are given by relations instead of literals:

```c
if (key[0] == 'b' && key[1] == 'c' && key[2] == 't' /* ... */)
  if (key[5] == '4')
    /* ... */
          if ((key[10] ^ key[9]) == 0x10)
            if (key[11] - 1 == key[8])
              if (key[12] == '!')
                if (key[13] == '}')
                  puts("Key accepted, activating...");
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/b01lers_crackme_2/crackme_2
```

```text
Input:
  stdin
  inferred length: 14

Goal:
  reaches 0x1013aa
  calls puts("Key correct, activating.")

Solver:
  backend: z3
  result: sat

Solution:
  bctf{4lg3br4!}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the relations tie characters to each other rather than to constants, which
  is what the solver is for: the xor and the offset are inverted along with the literals.
- **Answer:** the key is 14 characters and nothing checks what follows, so `solve` reports
  the shortest line that works.

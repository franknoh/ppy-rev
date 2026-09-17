# beleaf

| | |
|---|---|
| Origin | CSAW CTF Qualification Round 2019, rev 50 "beleaf" ([binary via a writeup archive](https://github.com/KevOrr/ctf-writeups/tree/master/2019/csaw/rev/beleaf)) |
| Binary | `beleaf`, x86-64 PIE ELF, stripped |
| Input | stdin (`scanf("%s")`) |
| Hints needed | `--length 33` |
| Answer | `flag{we_beleaf_in_your_re_future}` |

## The challenge

```text
$ ./beleaf
Enter the flag
>>> flag{guess}
Incorrect!
```

Each character is looked up in a binary search tree stored as an array, and the index it
is found at must match a table:

```c
scanf("%s", input);
if (strlen(input) < 33) { puts("Incorrect!"); exit(1); }
for (i = 0; i < strlen(input); i++)
    if (tree_index(input[i]) != expected[i]) { puts("Incorrect!"); exit(1); }
puts("Correct!");
```

```c
long tree_index(char c) {
    long i = 0;
    while (i != -1 && c != tree[i])
        i = c < tree[i] ? 2 * i + 1 : 2 * i + 2;
    return i;
}
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/csaw_beleaf/beleaf --length 33
```

```text
Input:
  stdin
  inferred length: 33

Goal:
  reaches 0x1009b4
  calls puts("Correct!")

Solver:
  backend: z3
  result: sat

Solution:
  flag{we_beleaf_in_your_re_future}
```

The slowest of these examples, at about two and a half minutes.

## Why the hint

The length check (`strlen < 33` fails) is plain in `main`. Telling `solve` the length saves
it from also exploring every longer input, each character of which forks a walk down the
tree. `--flag-format 'flag{*}'` can be added, but the length is what matters.

## How ppy-rev gets there

- **Main:** the binary is stripped and position independent; `_start` reaches
  `__libc_start_main` through the GOT, and `main` is the function it is given.
- **Input:** `scanf("%s")` reads a whitespace-free token from stdin.
- **Search:** for each character, the tree walk forks at every node (equal, less,
  greater), about six levels deep. Only the walk that ends at the expected index survives
  the comparison after it, so the search goes character by character. With 33 characters,
  that is about 10,000 states and 15,000 solver calls.

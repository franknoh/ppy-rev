# Bbbbloat

| | |
|---|---|
| Origin | picoCTF 2022, Reverse Engineering "Bbbbloat" ([binary via a writeup archive](https://github.com/HHousen/PicoCTF-2022/tree/master/Reverse%20Engineering/Bbbbloat)) |
| Binary | `bbbbloat`, x86-64 PIE ELF, stripped, padded with junk arithmetic |
| Input | stdin (`scanf("%d")`) |
| Hints needed | `--goal-address 0x1014d6` |
| Answer | `549255` (the program then prints the flag) |

## The challenge

```text
$ ./bbbbloat
What's my favorite number? 42
Sorry, that's not it!
```

Under the bloat, the check is a single comparison:

```c
scanf("%d", &number);
if (number == 0x86187) {
    /* decode the flag and print it */
} else {
    puts("Sorry, that's not it!");
}
```

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/picoctf_bbbbloat/bbbbloat --goal-address 0x1014d6
```

```text
Input:
  stdin
  inferred length: 6

Goal:
  reaches 0x1014d6

Solver:
  backend: z3
  result: sat

Solution:
  549255
```

About 12 seconds.

## Why the hint

The flag is decoded at run time, so the binary contains no success message, only the
failure one. `analyze` says so:

```text
$ uv run ppy-rev analyze examples/picoctf_bbbbloat/bbbbloat
Success candidates:
  none (pass --goal-address or --goal-string to solve)

Failure candidates:
  0.75  0x10158a  puts("Sorry, that's not it!") in FUN_00101307
```

The goal is then the code that runs when the number is right: the block after the
comparison with `0x86187`. Find it in the lifted IR (or any disassembler; Ghidra loads this
PIE at `0x100000`):

```bash
uv run ppy-rev lift examples/picoctf_bbbbloat/bbbbloat --emit-ir --function FUN_00101307
```

The comparison is near the end of the first block:

```text
    v36:32 = load v27                                       ; 0x1014c8:1
    v37:32 = sub v36, 0x86187:32                            ; 0x1014cb:2
    v38:8 = equal v37, 0x0:32                               ; 0x1014cb:4
    v39:8 = boolean_not v38                                 ; 0x1014d0:0
    branch v39, bb2, bb1                                    ; 0x1014d0:1
  bb1 @0x1014d6:
```

When the number equals `0x86187`, `v39` is false and execution continues at `bb1`, which
starts at `0x1014d6`.

## How ppy-rev gets there

- **Input:** `scanf("%d")` reads stdin. The model forks on the shape of the number (sign,
  digit count, where it ends) and tries short numbers first, so the answer is the plain
  `549255` rather than an equivalent like `+0000549255`.
- **Search:** one comparison decides everything; the bloat around it is concrete
  arithmetic that execution simply computes.

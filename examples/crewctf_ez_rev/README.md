# ez rev

| | |
|---|---|
| Origin | CrewCTF 2023, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/CrewCTF/2023/rev/ez_rev)) |
| Binary | `a.out`, x86-64 ELF, dynamically linked, stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `flag{ez_rev_goes_brrrrr....but_wait_a_seccond_the_format_flag_looks_weird}` |
| Native run | fails on any other glibc, whatever the input (see below) |

## The challenge

`main` is small and reads a line, then compares it with a table in `.data`:

```c
puts("[+] Another flag checker...");
fgets(input, 0x100, stdin);
for (i = 0; i < 0x4a; i++)
    if (input[i] != (expected[i] ^ 0x70)) { puts("[-] No :("); exit(-1); }
puts("[+] Correct!!");
```

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
  note: code runs before main: _INIT_1 calls exit, fgets, ptrace (not modeled)

Solution:
  flag{ez_rev_goes_brrrrr....but_wait_a_seccond_the_format_flag_looks_weird}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** 74 characters, one xor each. The table is static data, so the whole check is 74
  independent byte equalities and the solver answers immediately.
- **Goal:** `puts("[+] Correct!!")` outranks the banner `puts("[+] Another flag checker...")`,
  which the program prints before reading anything.

## Why `--verify` reports a native failure

This is the one example where running the real binary disagrees with the analysis, and it is
worth keeping for that reason:

```text
uv run ppy-rev solve examples/crewctf_ez_rev/a.out --verify

Verification:
  RevIR execution: passed (reaches the goal)
  native (sandboxed): failed (exit status 255, does not print "[+] Correct!!")
```

The binary has a second, much larger function that `.init_array` runs *before* `main`. It
calls `ptrace(PTRACE_TRACEME)`, prints the banner, reads a line of its own, and then
fingerprints the C library:

```c
if ((got[strlen] & 0xfff) + (got[a] & 0xfff) + (got[b] & 0xfff) != 0x1720 || ...) {
    puts("[-] Why you still here");
    exit(-1);
}
```

Those are the low 12 bits of libc addresses resolved at load time, so the test only holds on
the glibc the author built against. On anything else the program exits from its constructor:

```text
[+] Another flag checker...
[-] Why you still here
```

no matter what is typed. `ppy-rev` solves from `main` and does not model the initializers that
run before it, so it never sees that check. It does say one exists — the `note:` line above,
and in `ppy-rev analyze`:

```text
Runs before main:
  _INIT_1 at 0x40123e calls exit, fgets, ptrace
  not modeled: solving starts at main
```

Its answer is still the string `main` compares against, which is what the challenge asks for.
The honest reading of the two verification lines is exactly what they say: the reconstructed
program reaches the goal, and the original binary on this machine does not get that far.

`examples/check.sh` knows about the `Native run` row above and does not count this as a
regression when `VERIFY=1` is set.

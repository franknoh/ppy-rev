# PocketVM

| | |
|---|---|
| Origin | THJCC 2026, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/THJCC/2026/rev/PocketVM)) |
| Binary | `chall`, x86-64 PIE ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `THJCC{71ny_vm_5h311_p4ck}` |

## The challenge

A small virtual machine checks the flag: its bytecode pushes, xors, and compares the input
one byte at a time, and the interpreter reports `[+] correct` only if every instruction
agrees.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/thjcc_pocketvm/chall
```

```text
Input:
  stdin
  inferred length: 25

Goal:
  reaches 0x101224
  calls puts("[+] correct")

Solver:
  backend: z3
  result: sat

Solution:
  THJCC{71ny_vm_5h311_p4ck}

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** solving does not need to understand the VM: the interpreter loop runs over
  concrete bytecode, so each executed instruction turns into ordinary constraints on the
  input bytes.
- **Note:** `ppy-rev vm detect` does not report this dispatcher as likely (it has few
  handlers and a uniform program counter), which is why plain `solve` is the way in.

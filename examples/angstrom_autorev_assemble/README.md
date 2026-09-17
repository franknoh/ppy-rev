# Autorev Assemble

| | |
|---|---|
| Origin | ångstromCTF 2020, rev ([files](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/angstromCTF/2020/rev/Autorev_Assemble)) |
| Binary | `autorev_assemble`, x86-64 ELF, not stripped |
| Input | stdin (`fgets`) |
| Hints needed | none |
| Answer | `actf{wr0t3_4_pr0gr4m_t0_h3lp_y0u_w1th_th1s_df93171eb49e21a3a436e186bc68a5b2d8ed}` |

## The challenge

The joke of the challenge is its hundred one-line checks, each in its own function:

```c
bool f268(char *z) { return z[0xb9] == 'i'; }
bool f372(char *z) { return z[0xc4] == 'a'; }
/* ... about a hundred more ... */

fgets(z, 0x100, stdin);
if (f268(z) && f723(z) && f611(z) && f985(z) && /* ... */) puts("CORRECT");
```

The answer is a sentence with the flag inside it, so `solve` prints a whole line of
filler around the flag.

## Solve it

```bash
examples/fetch.sh
uv run ppy-rev solve examples/angstrom_autorev_assemble/autorev_assemble
```

```text
Input:
  stdin
  inferred length: 200

Goal:
  reaches 0x408953
  calls puts("CHALLENGE: SOLVED")

Solver:
  backend: z3
  result: sat

Solution:
  Blockchain big data solutions now with added machine learning. Enjoy! I sincerely hope you actf{wr0t3_4_pr0gr4m_t0_h3lp_y0u_w1th_th1s_df93171eb49e21a3a436e186bc68a5b2d8ed} instead of doing it by hand.

Verification:
  RevIR execution: passed (reaches the goal)
```

## How ppy-rev gets there

- **Search:** the checks are one long conjunction, so there is a single path; each call is
  followed into its function and adds one equality.
- **Answer:** only the positions some check mentions are pinned down, so the rest of the
  line is whatever the solver picked.

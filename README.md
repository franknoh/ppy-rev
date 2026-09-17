# ppy-rev

`ppy-rev` lifts ELF binaries through Ghidra into a small typed intermediate
representation (RevIR), emits readable [PPy](https://github.com/franknoh/PPy),
and solves simple reversing challenges with purpose-built symbolic execution
over Z3.

## Supported targets

Linux ELF, x86-64, little-endian. Floating-point p-code and processor-specific
user operations are lifted as explicit unsupported operations rather than
approximated.

## Installation

Requires Python 3.12, [uv](https://docs.astral.sh/uv/), a JDK 21, and
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.1.3.

```bash
uv sync --frozen
export PPY_REV_GHIDRA_HOME=/path/to/ghidra_12.1.3_PUBLIC
```

`ppy-rev` never downloads Ghidra itself. The Docker image (`docker compose build`)
contains a checksum-verified Ghidra and every tool the test suite needs.

## Commands

```bash
ppy-rev info ./chall                # architecture, entry point, sections, functions
ppy-rev lift ./chall --emit-ir      # simplified RevIR for every recovered function (--no-simplify: raw)
ppy-rev lift ./chall --emit-ir --function main -o main.revir
```

Ghidra analysis runs headlessly in a throwaway project. Validated exports are
cached under `$PPY_REV_CACHE_DIR` (default `~/.cache/ppy-rev`), keyed by the
binary's SHA-256, the Ghidra version, the export bridge sources, and the
analysis options; `--no-cache` forces a fresh analysis.

## Architecture

```text
ELF ─► Ghidra headless ─► versioned JSON export ─► RevIR (SSA) ─► consumers
```

- `ppy_rev.ghidra`: the Java export bridge (`bridge/*.java`, extraction only),
  the headless runner, the export schema parser, and the cache.
- `ppy_rev.lift`: raw p-code → RevIR. Control flow is recovered at p-code
  granularity; registers and temporaries become SSA values; calls and returns
  carry register state explicitly.
- `ppy_rev.ir`: the immutable RevIR model, its reference concrete semantics, text
  form, CFG utilities, and a structural validator (single definitions, dominance,
  operation widths).
- `ppy_rev.simplify`: interprocedural register-interface narrowing, constant folding
  with width-exact identities, common subexpression elimination, block-local
  store/load forwarding, dead code elimination, and CFG cleanup. Operations that
  may fault are never removed.
- `ppy_rev.execution`: a strict concrete RevIR interpreter with an explicit memory
  model. It is the semantic oracle: tests compare it against native execution of
  the same compiled code, before and after simplification.

RevIR values have explicit bit widths; signedness belongs to operations.
Lifting is based on raw p-code (exact instruction semantics); Ghidra's
decompiler output (high p-code, prototypes, symbols) is exported alongside it
as metadata.

## Development

```bash
scripts/check.sh                    # ruff, pyright, Java bridge build, pytest
scripts/build_fixtures.sh           # compile C fixtures with gcc/clang at -O0..-O3
docker compose build && docker compose run --rm dev scripts/check.sh
```

Tests that need Ghidra or a compiler are skipped when the tool is missing,
unless `PPY_REV_REQUIRE_TOOLS=1` (set in the Docker image) turns that into a
failure. `PPY_REV_UPDATE_GOLDEN=1` rewrites golden RevIR after an intentional
change.

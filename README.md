# ppy-rev

`ppy-rev` lifts ELF binaries through Ghidra into a small typed intermediate
representation (RevIR), emits readable [PPy](https://github.com/franknoh/PPy),
and solves simple reversing challenges with purpose-built symbolic execution
over Z3.

## Development

```bash
uv sync --frozen
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
```

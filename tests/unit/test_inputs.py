"""Input constraints mean what the options say, for every input they could describe."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ppy_rev.symbolic.evaluate import evaluate
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.inputs import (
    NEWLINE,
    argv_constraints,
    argv_symbols,
    stdin_constraints,
    stdin_symbols,
)

CAPACITY = 8
hints = st.binary(max_size=3)
lengths = st.none() | st.integers(0, CAPACITY)


def _holds(constraints: list[Expr], symbols: tuple[Expr, ...], data: bytes) -> bool:
    assignment = {str(symbol.name): byte for symbol, byte in zip(symbols, data, strict=True)}
    return all(evaluate(item, assignment) for item in constraints)


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=CAPACITY), lengths, hints, hints)
def test_argv_prefix_suffix_and_length(
    text: bytes, length: int | None, prefix: bytes, suffix: bytes
) -> None:
    text = text.replace(b"\0", b"a")
    symbols = argv_symbols(1, CAPACITY)
    constraints = argv_constraints(symbols, length, prefix, suffix, None)
    expected = (
        text.startswith(prefix)
        and text.endswith(suffix)
        and (length is None or len(text) == length)
    )
    assert _holds(constraints, symbols, text.ljust(CAPACITY, b"\0")) == expected


@settings(max_examples=300, deadline=None)
@given(st.binary(min_size=CAPACITY, max_size=CAPACITY), lengths, hints, hints)
def test_stdin_first_line_prefix_suffix_and_length(
    stream: bytes, length: int | None, prefix: bytes, suffix: bytes
) -> None:
    symbols = stdin_symbols(CAPACITY)
    constraints = stdin_constraints(symbols, length, prefix, suffix, None)
    newline = stream.find(bytes([NEWLINE]))
    line = stream if newline < 0 else stream[:newline]
    if length is None:
        suffix_holds = line.endswith(suffix)
    else:
        # With a length, the line ends there, and the suffix is the bytes just before it.
        suffix_holds = len(suffix) <= length and stream[:length].endswith(suffix)
    expected = (
        stream.startswith(prefix) and suffix_holds and (length is None or len(line) == length)
    )
    assert _holds(constraints, symbols, stream) == expected

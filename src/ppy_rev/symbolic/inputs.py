"""Symbolic models of program inputs and the user's explicit constraints on them.

An argv string is modeled as `max_length` symbolic bytes followed by a concrete NUL, with
every byte after the first NUL also NUL: the solution is the bytes before the first NUL,
and it can never contain an embedded NUL, just like a real argument. No character set is
assumed unless the user asks for one.
"""

from __future__ import annotations

import re
from enum import StrEnum

from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.expr import Expr

NEWLINE = 0x0A


class Charset(StrEnum):
    PRINTABLE = "printable"
    ASCII = "ascii"
    ALPHANUMERIC = "alnum"
    ALPHA = "alpha"
    DIGITS = "digits"
    HEX = "hex"


_RANGES: dict[Charset, tuple[tuple[int, int], ...]] = {
    Charset.PRINTABLE: ((0x20, 0x7E),),
    Charset.ASCII: ((0x01, 0x7F),),
    Charset.ALPHANUMERIC: ((0x30, 0x39), (0x41, 0x5A), (0x61, 0x7A)),
    Charset.ALPHA: ((0x41, 0x5A), (0x61, 0x7A)),
    Charset.DIGITS: ((0x30, 0x39),),
    Charset.HEX: ((0x30, 0x39), (0x41, 0x46), (0x61, 0x66)),
}


def charset_values(charset: Charset | None) -> tuple[int, ...]:
    """Every byte value the charset admits; printable ASCII when none is given."""
    ranges = _RANGES[charset] if charset is not None else _RANGES[Charset.PRINTABLE]
    return tuple(value for low, high in ranges for value in range(low, high + 1))


def in_charset(byte: Expr, charset: Charset) -> Expr:
    return sx.bool_or(
        *(
            sx.bool_and(
                sx.unsigned_less_equal(sx.const(low, 8), byte),
                sx.unsigned_less_equal(byte, sx.const(high, 8)),
            )
            for low, high in _RANGES[charset]
        )
    )


def argv_symbols(index: int, length: int) -> tuple[Expr, ...]:
    return tuple(sx.symbol(f"argv{index}_{position:03}", 8) for position in range(length))


def stdin_symbols(length: int) -> tuple[Expr, ...]:
    return tuple(sx.symbol(f"stdin_{position:04}", 8) for position in range(length))


def file_symbols(name: str, length: int) -> tuple[Expr, ...]:
    """Bytes of a file the program reads; its name keeps them apart from other inputs."""
    safe = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return tuple(sx.symbol(f"file_{safe}_{position:04}", 8) for position in range(length))


def _is(byte: Expr, value: int) -> Expr:
    return sx.equal(byte, sx.const(value, 8))


def argv_constraints(
    symbols: tuple[Expr, ...],
    length: int | None,
    prefix: bytes,
    suffix: bytes,
    charset: Charset | None,
) -> list[Expr]:
    constraints: list[Expr] = []
    for position in range(len(symbols) - 1):
        # Once the string has ended, the rest of the reserved bytes stay NUL.
        constraints.append(
            sx.bool_or(sx.bool_not(_is(symbols[position], 0)), _is(symbols[position + 1], 0))
        )
    if length is not None:
        constraints.extend(sx.bool_not(_is(symbol, 0)) for symbol in symbols[:length])
        if length < len(symbols):
            constraints.append(_is(symbols[length], 0))
    if 0 in prefix or 0 in suffix:
        constraints.append(sx.FALSE)  # an argument never contains a NUL byte
    constraints.extend(_is(symbols[position], byte) for position, byte in enumerate(prefix))
    if suffix:
        # The string ends at `end`: a NUL there (or the terminator after the reserved
        # bytes), and none before it.
        ends: list[tuple[int, Expr]] = []
        for end in range(len(suffix), len(symbols) + 1):
            terminated = _is(symbols[end], 0) if end < len(symbols) else sx.TRUE
            ends.append((end, sx.bool_and(terminated, sx.bool_not(_is(symbols[end - 1], 0)))))
        constraints.append(_ends_with(symbols, suffix, length, ends))
    if charset is not None:
        constraints.extend(
            sx.bool_or(_is(symbol, 0), in_charset(symbol, charset)) for symbol in symbols
        )
    return constraints


def stdin_constraints(
    symbols: tuple[Expr, ...],
    line_length: int | None,
    prefix: bytes,
    suffix: bytes,
    charset: Charset | None,
) -> list[Expr]:
    constraints: list[Expr] = []
    if line_length is not None:
        constraints.extend(sx.bool_not(_is(symbol, NEWLINE)) for symbol in symbols[:line_length])
        if line_length < len(symbols):
            constraints.append(_is(symbols[line_length], NEWLINE))
    constraints.extend(_is(symbols[position], byte) for position, byte in enumerate(prefix))
    if suffix:
        # The first line ends at `end`: a newline there and none before it, or no newline
        # anywhere in the bytes offered.
        ends: list[tuple[int, Expr]] = []
        no_newline = sx.TRUE
        for end, symbol in enumerate(symbols):
            if end >= len(suffix):
                ends.append((end, sx.bool_and(no_newline, _is(symbol, NEWLINE))))
            no_newline = sx.bool_and(no_newline, sx.bool_not(_is(symbol, NEWLINE)))
        if len(symbols) >= len(suffix):
            ends.append((len(symbols), no_newline))
        constraints.append(_ends_with(symbols, suffix, line_length, ends))
    if charset is not None:
        constraints.extend(
            sx.bool_or(_is(symbol, NEWLINE), in_charset(symbol, charset)) for symbol in symbols
        )
    return constraints


def _ends_with(
    symbols: tuple[Expr, ...], suffix: bytes, length: int | None, ends: list[tuple[int, Expr]]
) -> Expr:
    """The input ends with `suffix`, wherever it ends (at `length`, when that is given)."""

    def matches(end: int) -> Expr:
        start = end - len(suffix)
        return sx.bool_and(
            *(_is(symbols[start + offset], byte) for offset, byte in enumerate(suffix))
        )

    if length is not None:
        return matches(length) if len(suffix) <= length <= len(symbols) else sx.FALSE
    return sx.bool_or(*(sx.bool_and(condition, matches(end)) for end, condition in ends))


def argv_solution(symbols: tuple[Expr, ...], model: dict[str, int]) -> bytes:
    values = bytes(model.get(symbol.name, 0) for symbol in symbols)
    end = values.find(b"\0")
    return values if end < 0 else values[:end]


def stdin_solution(
    symbols: tuple[Expr, ...], model: dict[str, int], reads: list[tuple[int, int, bool]]
) -> bytes:
    """The bytes the program actually consumed, in order.

    A line-based read consumes through its newline; bytes after it in the same window were
    offered but not taken.
    """
    values = bytes(model.get(symbol.name, 0) for symbol in symbols)
    consumed = 0
    for start, end, line_based in reads:
        if start < consumed:
            continue
        window = values[start:end]
        if line_based:
            newline = window.find(b"\n")
            if newline >= 0:
                window = window[: newline + 1]
        consumed = start + len(window)
    return values[:consumed]

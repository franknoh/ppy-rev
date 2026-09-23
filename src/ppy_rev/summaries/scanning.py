"""Decimal number parsing and `scanf` formats, as glibc performs them in the C locale.

Supported `scanf` directives: whitespace, ordinary characters, and the conversions `%s`,
`%c`, `%d`, and `%u` with an optional `*`, width, and integer length modifier (`hh`, `h`,
`l`, `ll`). Anything else is rejected rather than approximated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from ppy_rev.summaries.ctype import WHITESPACE

LONG_MAX = (1 << 63) - 1
LONG_MIN = -(1 << 63)
EOF = -1

_CONVERSION = re.compile(rb"%(\*?)(\d*)(hh|h|ll|l)?([a-zA-Z%\[])")
_STORE_SIZES = {None: 4, b"hh": 1, b"h": 2, b"l": 8, b"ll": 8}


class FormatError(Exception):
    pass


class DirectiveKind(StrEnum):
    SPACE = "space"
    LITERAL = "literal"
    STRING = "s"
    CHARACTERS = "c"
    DECIMAL = "d"
    SCANSET = "["


@dataclass(frozen=True, slots=True)
class Directive:
    kind: DirectiveKind
    literal: int = 0
    width: int | None = None
    store_size: int = 0
    """Bytes of the integer a `%d` conversion stores."""
    base: int = 10
    """The radix of a `%d`/`%u` (10), `%x` (16), or `%o` (8) conversion."""
    assigns: bool = True
    """False for conversions suppressed with `*`."""
    charset: frozenset[int] = frozenset()
    """The byte values a `%[` scanset matches (before negation)."""
    negated: bool = False
    """True for `%[^...]`: the scanset matches bytes NOT in `charset`."""


def parse_format(template: bytes) -> list[Directive]:
    directives: list[Directive] = []
    position = 0
    while position < len(template):
        byte = template[position]
        if byte in WHITESPACE:
            while position < len(template) and template[position] in WHITESPACE:
                position += 1
            directives.append(Directive(DirectiveKind.SPACE))
            continue
        if byte != ord("%"):
            directives.append(Directive(DirectiveKind.LITERAL, literal=byte))
            position += 1
            continue
        match = _CONVERSION.match(template, position)
        if match is None:
            raise FormatError(f"malformed conversion at {template[position:]!r}")
        suppressed, width_text, length, conversion = match.groups()
        position = match.end()
        width = int(width_text) if width_text else None
        if width == 0:
            raise FormatError("a conversion width of zero is undefined")
        if conversion == b"%" and not suppressed and width is None and length is None:
            # "%%" skips whitespace, then matches a percent sign.
            directives.append(Directive(DirectiveKind.SPACE))
            directives.append(Directive(DirectiveKind.LITERAL, literal=ord("%")))
        elif conversion in (b"s", b"c") and length is None:
            kind = DirectiveKind.STRING if conversion == b"s" else DirectiveKind.CHARACTERS
            directives.append(Directive(kind, width=width, assigns=not suppressed))
        elif conversion in (b"d", b"u", b"x", b"X", b"o"):
            # `%u` reads the same decimal token as `%d`; `%x`/`%o` read hex/octal. All store
            # only the low `store_size` bytes, so signedness does not change a crackme's value.
            directives.append(
                Directive(
                    DirectiveKind.DECIMAL,
                    width=width,
                    store_size=_STORE_SIZES[length],
                    base={b"x": 16, b"X": 16, b"o": 8}.get(conversion, 10),
                    assigns=not suppressed,
                )
            )
        elif conversion == b"[" and length is None:
            charset, negated, position = _parse_scanset(template, position)
            directives.append(
                Directive(
                    DirectiveKind.SCANSET,
                    width=width,
                    charset=charset,
                    negated=negated,
                    assigns=not suppressed,
                )
            )
        else:
            raise FormatError(f"unsupported conversion {match.group(0)!r}")
    return directives


def _parse_scanset(template: bytes, position: int) -> tuple[frozenset[int], bool, int]:
    """Parse a `%[...]` set body, starting just past the `[`; return (bytes, negated, end).

    Follows the C rules: a leading `^` negates, a `]` right after the `[` (or the `^`) is an
    ordinary member, and `a-z` is a range. The set ends at the next `]`.
    """
    negated = position < len(template) and template[position] == ord("^")
    if negated:
        position += 1
    members: set[int] = set()
    if position < len(template) and template[position] == ord("]"):
        members.add(ord("]"))
        position += 1
    previous: int | None = None
    while position < len(template) and template[position] != ord("]"):
        byte = template[position]
        if (
            byte == ord("-")
            and previous is not None
            and position + 1 < len(template)
            and template[position + 1] != ord("]")
        ):
            high = template[position + 1]
            low, high = (previous, high) if previous <= high else (high, previous)
            members.update(range(low, high + 1))
            previous = None
            position += 2
        else:
            members.add(byte)
            previous = byte
            position += 1
    if position >= len(template):
        raise FormatError("a scanset with no closing ]")
    return frozenset(members), negated, position + 1


def _is_base_digit(byte: int, base: int) -> bool:
    """Whether `byte` is a digit in the given radix (10, 16, or 8)."""
    if base == 16:
        return 0x30 <= byte <= 0x39 or 0x41 <= byte <= 0x46 or 0x61 <= byte <= 0x66
    if base == 8:
        return 0x30 <= byte <= 0x37
    return 0x30 <= byte <= 0x39


def clamp_decimal(negative: bool, magnitude: int) -> int:
    """strtol's result for a sign and the digits' value: saturated at the long range."""
    if negative:
        return LONG_MIN if magnitude > -LONG_MIN else -magnitude
    return min(magnitude, LONG_MAX)


def parse_hex(data: bytes, start: int = 0) -> Number:
    """strtoul(data + start, &end, 16): whitespace, a sign, an optional `0x`, hex digits.

    The `0x`/`0X` prefix is consumed only when a hex digit follows it, exactly as glibc
    does; the magnitude saturates at `ULONG_MAX`, and a leading `-` wraps modulo 2**64.
    """
    mask64 = (1 << 64) - 1
    position = start
    while position < len(data) and data[position] in WHITESPACE:
        position += 1
    negative = False
    if position < len(data) and data[position] in b"+-":
        negative = data[position] == ord("-")
        position += 1
    if (
        position + 2 < len(data)
        and data[position] == 0x30
        and data[position + 1] in b"xX"
        and _is_base_digit(data[position + 2], 16)
    ):
        position += 2
    first = position
    value = 0
    while position < len(data) and _is_base_digit(data[position], 16):
        value = value * 16 + int(chr(data[position]), 16)
        position += 1
    if position == first:
        return Number(0, start)
    value = min(value, mask64)
    return Number((-value) & mask64 if negative else value, position)


@dataclass(frozen=True, slots=True)
class Number:
    value: int
    """The saturated long value."""
    end: int
    """Index just past the last digit; the start index when there are no digits."""


def parse_long(data: bytes, start: int = 0) -> Number:
    """strtol(data + start, &end, 10), reading until the first byte that does not fit."""
    position = start
    while position < len(data) and data[position] in WHITESPACE:
        position += 1
    negative = False
    if position < len(data) and data[position] in b"+-":
        negative = data[position] == ord("-")
        position += 1
    first_digit = position
    magnitude = 0
    while position < len(data) and 0x30 <= data[position] <= 0x39:
        magnitude = magnitude * 10 + data[position] - 0x30
        position += 1
    if position == first_digit:
        return Number(0, start)
    return Number(clamp_decimal(negative, magnitude), position)


@dataclass(frozen=True, slots=True)
class Assignment:
    directive: Directive
    content: bytes | int


@dataclass(frozen=True, slots=True)
class ScanResult:
    result: int
    """What scanf returns: assignments made, or EOF."""
    consumed: int
    assignments: tuple[Assignment, ...]


SKIPS_WHITESPACE = frozenset({DirectiveKind.SPACE, DirectiveKind.STRING, DirectiveKind.DECIMAL})


def scan(directives: list[Directive], data: bytes) -> ScanResult:
    """Run `directives` over a stream whose remaining bytes are `data`.

    Like glibc, an input failure (end of input) before any assignment returns EOF, and a
    matching failure returns the assignments made so far, leaving the offending byte
    unread.
    """
    position = 0
    assigned: list[Assignment] = []

    def finish(input_failure: bool) -> ScanResult:
        result = EOF if input_failure and not assigned else len(assigned)
        return ScanResult(result, position, tuple(assigned))

    for directive in directives:
        if directive.kind in SKIPS_WHITESPACE:
            while position < len(data) and data[position] in WHITESPACE:
                position += 1
        if directive.kind is DirectiveKind.SPACE:
            continue
        if position >= len(data):
            return finish(input_failure=True)
        match directive.kind:
            case DirectiveKind.LITERAL:
                if data[position] != directive.literal:
                    return finish(input_failure=False)
                position += 1
                continue
            case DirectiveKind.STRING:
                end = position
                limit = len(data) if directive.width is None else position + directive.width
                while end < min(limit, len(data)) and data[end] not in WHITESPACE:
                    end += 1
                content: bytes | int = data[position:end]
                position = end
            case DirectiveKind.CHARACTERS:
                # Ending the input part way still assigns the characters that were read.
                content = data[position : position + (directive.width or 1)]
                position += len(content)
            case DirectiveKind.SCANSET:
                end = position
                limit = len(data) if directive.width is None else position + directive.width
                while end < min(limit, len(data)) and (
                    (data[end] in directive.charset) != directive.negated
                ):
                    end += 1
                if end == position:
                    return finish(input_failure=False)  # nothing matched: a matching failure
                content = data[position:end]
                position = end
            case DirectiveKind.DECIMAL:
                limit = len(data) if directive.width is None else position + directive.width
                limit = min(limit, len(data))
                negative = data[position] == ord("-")
                digits = position + 1 if data[position] in b"+-" else position
                end = digits
                while end < limit and _is_base_digit(data[end], directive.base):
                    end += 1
                if end == digits:
                    position = digits  # a sign alone is consumed before the failure
                    return finish(input_failure=False)
                magnitude = int(data[digits:end], directive.base)
                if directive.base == 10:
                    content = clamp_decimal(negative, magnitude)
                else:
                    content = (-magnitude if negative else magnitude) & ((1 << 64) - 1)
                position = end
        if directive.assigns:
            assigned.append(Assignment(directive, content))
    return finish(input_failure=False)

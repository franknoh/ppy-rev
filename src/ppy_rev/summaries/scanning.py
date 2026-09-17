"""Decimal number parsing and `scanf` formats, as glibc performs them in the C locale.

Supported `scanf` directives: whitespace, ordinary characters, and the conversions `%s`,
`%c`, and `%d` with an optional `*`, width, and integer length modifier (`hh`, `h`, `l`,
`ll`). Anything else is rejected rather than approximated.
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


@dataclass(frozen=True, slots=True)
class Directive:
    kind: DirectiveKind
    literal: int = 0
    width: int | None = None
    store_size: int = 0
    """Bytes of the integer a `%d` conversion stores."""
    assigns: bool = True
    """False for conversions suppressed with `*`."""


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
        elif conversion == b"d":
            directives.append(
                Directive(
                    DirectiveKind.DECIMAL,
                    width=width,
                    store_size=_STORE_SIZES[length],
                    assigns=not suppressed,
                )
            )
        else:
            raise FormatError(f"unsupported conversion {match.group(0)!r}")
    return directives


def clamp_decimal(negative: bool, magnitude: int) -> int:
    """strtol's result for a sign and the digits' value: saturated at the long range."""
    if negative:
        return LONG_MIN if magnitude > -LONG_MIN else -magnitude
    return min(magnitude, LONG_MAX)


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
            case DirectiveKind.DECIMAL:
                limit = len(data) if directive.width is None else position + directive.width
                limit = min(limit, len(data))
                negative = data[position] == ord("-")
                digits = position + 1 if data[position] in b"+-" else position
                end = digits
                while end < limit and 0x30 <= data[end] <= 0x39:
                    end += 1
                if end == digits:
                    position = digits  # a sign alone is consumed before the failure
                    return finish(input_failure=False)
                content = clamp_decimal(negative, int(data[digits:end]))
                position = end
        if directive.assigns:
            assigned.append(Assignment(directive, content))
    return finish(input_failure=False)

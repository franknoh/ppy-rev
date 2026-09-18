"""A byte-exact subset of printf formatting for integer and string conversions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ppy_rev.execution.memory import ConcreteMemory
from ppy_rev.ir.semantics import to_signed

_SPECIFIER = re.compile(rb"%([-+ #0]*)(\d*)(?:\.(\d+))?(hh|h|ll|l|z|j|t)?([diouxXcsp%])")
_WIDTHS = {b"hh": 8, b"h": 16, b"l": 64, b"ll": 64, b"z": 64, b"j": 64, b"t": 64}


class FormatError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Directive:
    """One conversion in a format string, with the flags that decide its width."""

    flags: bytes
    width: bytes
    precision: bytes | None
    length: bytes | None
    conversion: bytes

    @property
    def bits(self) -> int:
        return _WIDTHS.get(self.length or b"", 32)


type Piece = bytes | Directive
"""Literal text, or a conversion to apply to the next argument."""


def parse_format(template: bytes) -> list[Piece]:
    """Split a format string into the text it prints and the conversions it applies."""
    pieces: list[Piece] = []
    position = 0
    while position < len(template):
        percent = template.find(b"%", position)
        if percent < 0:
            pieces.append(template[position:])
            break
        if percent > position:
            pieces.append(template[position:percent])
        match = _SPECIFIER.match(template, percent)
        if match is None:
            raise FormatError(
                f"unsupported format directive at {template[percent : percent + 8]!r}"
            )
        flags, width, precision, length, conversion = match.groups()
        position = match.end()
        if conversion == b"%":
            pieces.append(b"%")
            continue
        pieces.append(Directive(flags, width, precision, length, conversion))
    return pieces


def format_printf(template: bytes, values: list[int], memory: ConcreteMemory) -> bytes:
    output = bytearray()
    position = 0
    index = 0
    while position < len(template):
        percent = template.find(b"%", position)
        if percent < 0:
            output += template[position:]
            break
        output += template[position:percent]
        match = _SPECIFIER.match(template, percent)
        if match is None:
            raise FormatError(
                f"unsupported format directive at {template[percent : percent + 8]!r}"
            )
        flags, width, precision, length, conversion = match.groups()
        position = match.end()
        if conversion == b"%":
            output += b"%"
            continue
        if index >= len(values):
            raise FormatError("format needs more arguments than the registers provide")
        value = values[index]
        index += 1
        output += _convert(flags, width, precision, length, conversion, value, memory)
    return bytes(output)


def format_one(directive: Directive, value: int, memory: ConcreteMemory | None = None) -> bytes:
    """What one conversion writes for a value that is already known."""
    return _convert(
        directive.flags,
        directive.width,
        directive.precision,
        directive.length,
        directive.conversion,
        value,
        memory,
    )


def _convert(
    flags: bytes,
    width: bytes,
    precision: bytes | None,
    length: bytes | None,
    conversion: bytes,
    value: int,
    memory: ConcreteMemory | None,
) -> bytes:
    bits = _WIDTHS.get(length or b"", 32)
    value &= (1 << bits) - 1
    match conversion:
        case b"d" | b"i":
            body = str(to_signed(value, bits)).encode()
        case b"u":
            body = str(value).encode()
        case b"x":
            body = f"{value:x}".encode()
        case b"X":
            body = f"{value:X}".encode()
        case b"o":
            body = f"{value:o}".encode()
        case b"c":
            body = bytes([value & 0xFF])
        case b"p":
            body = f"{value:#x}".encode() if value else b"(nil)"
        case _:
            if memory is None:
                raise FormatError("a string conversion needs memory to read from")
            text = memory.read_c_string(value & ((1 << 64) - 1))
            body = text if precision is None else text[: int(precision)]
    if precision is not None and conversion not in (b"s", b"c"):
        digits = body.lstrip(b"-")
        body = (b"-" if body.startswith(b"-") else b"") + digits.rjust(int(precision), b"0")
    if b"#" in flags and conversion in (b"x", b"X") and value:
        body = b"0" + conversion + body
    if b"+" in flags and conversion in (b"d", b"i") and not body.startswith(b"-"):
        body = b"+" + body
    target = int(width) if width else 0
    if len(body) < target:
        if b"-" in flags:
            body = body.ljust(target)
        elif b"0" in flags and precision is None and conversion not in (b"s", b"c"):
            sign = body[:1] if body[:1] in (b"-", b"+") else b""
            body = sign + body[len(sign) :].rjust(target - len(sign), b"0")
        else:
            body = body.rjust(target)
    return body

"""The C locale's character tables, laid out as glibc exposes them.

`__ctype_b_loc()` returns a pointer to a pointer into a table of classification flags that
can be indexed from -128 (signed `char` values) to 255; `__ctype_toupper_loc()` and
`__ctype_tolower_loc()` do the same for 32-bit case mappings. The `is*` functions and
`toupper`/`tolower` read the same tables.
"""

from __future__ import annotations

import struct

FIRST = -128
LAST = 255
ENTRIES = LAST - FIRST + 1


def _bit(position: int) -> int:
    # glibc stores the flags big-endian within the 16-bit entry.
    return (1 << position) << 8 if position < 8 else (1 << position) >> 8


UPPER, LOWER, ALPHA, DIGIT, XDIGIT, SPACE, PRINT, GRAPH, BLANK, CNTRL, PUNCT, ALNUM = (
    _bit(position) for position in range(12)
)

CLASSIFIERS: dict[str, int] = {
    "isalnum": ALNUM,
    "isalpha": ALPHA,
    "isblank": BLANK,
    "iscntrl": CNTRL,
    "isdigit": DIGIT,
    "isgraph": GRAPH,
    "islower": LOWER,
    "isprint": PRINT,
    "ispunct": PUNCT,
    "isspace": SPACE,
    "isupper": UPPER,
    "isxdigit": XDIGIT,
}

WHITESPACE = frozenset({0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20})
"""`isspace` in the C locale."""


def classification(character: int) -> int:
    """The flags for table index `character` (-128..255)."""
    if not 0 <= character < 0x80:
        return 0
    flags = 0
    if 0x41 <= character <= 0x5A:
        flags |= UPPER | ALPHA | ALNUM
    if 0x61 <= character <= 0x7A:
        flags |= LOWER | ALPHA | ALNUM
    if 0x30 <= character <= 0x39:
        flags |= DIGIT | ALNUM | XDIGIT
    if 0x41 <= character <= 0x46 or 0x61 <= character <= 0x66:
        flags |= XDIGIT
    if character in WHITESPACE:
        flags |= SPACE
    if 0x20 <= character <= 0x7E:
        flags |= PRINT
    if 0x21 <= character <= 0x7E:
        flags |= GRAPH
        if not flags & ALNUM:
            flags |= PUNCT
    if character in (0x09, 0x20):
        flags |= BLANK
    if character < 0x20 or character == 0x7F:
        flags |= CNTRL
    return flags


def _case_table(first: int, last: int, delta: int, character: int) -> int:
    if first <= character <= last:
        return character + delta
    if FIRST <= character <= -2:
        return character + 0x100  # signed char values map to their unsigned byte
    return character


def to_upper(character: int) -> int:
    """`toupper`: the table entry within -128..255, the argument itself outside it."""
    return _case_table(0x61, 0x7A, -0x20, character)


def to_lower(character: int) -> int:
    return _case_table(0x41, 0x5A, 0x20, character)


def classification_table() -> bytes:
    return b"".join(struct.pack("<H", classification(index)) for index in range(FIRST, LAST + 1))


def upper_table() -> bytes:
    return b"".join(struct.pack("<i", to_upper(index)) for index in range(FIRST, LAST + 1))


def lower_table() -> bytes:
    return b"".join(struct.pack("<i", to_lower(index)) for index in range(FIRST, LAST + 1))

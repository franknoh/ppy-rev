"""What the C++ standard library looks like in memory, for the models to agree on.

Only the parts a beginner challenge uses: a `std::string` that a line is read into and
then compared, and stream output. libstdc++'s layout is used exactly, because optimized
code reads the fields itself instead of calling `size()` and `data()`.

    struct string { char *data; size_t size; union { char buffer[16]; size_t capacity; }; }

A string shorter than 16 bytes lives in `buffer` and `data` points at it.
"""

from __future__ import annotations

DATA = 0
SIZE = 8
BUFFER = 16
CAPACITY = 16
SMALL = 15
"""Longest string the object holds without allocating."""
SIZE_OF = 32

NAMES = {
    "operator<<": "std::ostream::operator<<",
    "~string": "std::string::~string",
    "string": "std::string::string",
    "size": "std::string::size",
    "length": "std::string::size",
    "data": "std::string::data",
    "c_str": "std::string::data",
    "empty": "std::string::empty",
    "operator[]": "std::string::at",
    "at": "std::string::at",
    "begin": "std::string::begin",
    "end": "std::string::end",
}
"""Demangled names Ghidra gives libstdc++ imports, mapped to what the models call them."""

PREFIXED = {
    "getline<": "std::getline",
    "endl<": "std::endl",
    "operator<<": "std::ostream::operator<<",
    "operator==": "std::string::operator==",
}
"""Templates, whose demangled names carry their arguments."""


def canonical(name: str) -> str | None:
    """The model name for a demangled C++ symbol, or None when it is not one we know."""
    for prefix, canonical_name in PREFIXED.items():
        if name.startswith(prefix):
            return canonical_name
    return NAMES.get(name)

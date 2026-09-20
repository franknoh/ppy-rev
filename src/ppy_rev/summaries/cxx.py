"""What the C++ standard library looks like in memory, for the models to agree on.

Only the parts a beginner challenge uses: a `std::string` that a line is read into and
then compared, and stream output. libstdc++'s layout is used exactly, because optimized
code reads the fields itself instead of calling `size()` and `data()`.

    struct string { char *data; size_t size; union { char buffer[16]; size_t capacity; }; }

A string shorter than 16 bytes lives in `buffer` and `data` points at it.

Which function an import is comes from the name the linker sees, not from Ghidra's
demangling: `size` and `data` are ordinary C names too, while `_ZNKSt7__cxx1112basic_...`
can only be one thing.
"""

from __future__ import annotations

DATA = 0
SIZE = 8
BUFFER = 16
CAPACITY = 16
SMALL = 15
"""Longest string the object holds without allocating."""
SIZE_OF = 32

_STRING = "basic_string"
_ISTREAM = "basic_istream"
_OSTREAM = "basic_ostream"


def from_symbol(symbol: str) -> str | None:
    """The model name for a mangled libstdc++ symbol, or None when it is not one we know."""
    if not symbol.startswith("_Z"):
        return None
    runtime = _RUNTIME.get(symbol.split("@", 1)[0])
    if runtime is not None:
        return runtime
    if "7getline" in symbol and _STRING in symbol:
        return "std::getline"
    if symbol.startswith("_ZSt") and "rs" in symbol and _ISTREAM in symbol and _STRING in symbol:
        return "std::istream::operator>>"
    if symbol.startswith("_ZSt4endl"):
        return "std::endl"
    if _OSTREAM in symbol or symbol.startswith("_ZNSols"):
        return "std::ostream::operator<<"
    if _STRING not in symbol:
        return None
    for suffix, name in _STRING_MEMBERS.items():
        if symbol.endswith(suffix):
            return name
    return None


_STRING_MEMBERS = {
    "4sizeEv": "std::string::size",
    "6lengthEv": "std::string::size",
    "4dataEv": "std::string::data",
    "5c_strEv": "std::string::data",
    "5emptyEv": "std::string::empty",
    "ixEm": "std::string::at",
    "2atEm": "std::string::at",
    "5beginEv": "std::string::begin",
    "3endEv": "std::string::end",
    "C1Ev": "std::string::string",
    "C2Ev": "std::string::string",
    "C1EPKcRKS3_": "std::string::string",
    "C1EPKc": "std::string::string",
    "D1Ev": "std::string::~string",
    "D2Ev": "std::string::~string",
    "10_M_disposeEv": "std::string::~string",
}
"""Mangled endings of the `std::string` members a challenge is likely to call."""


_RUNTIME = {
    "_Znwm": "operator new",
    "_Znam": "operator new",
    "_ZnwmSt11align_val_t": "operator new",
    "_ZdlPv": "operator delete",
    "_ZdaPv": "operator delete",
    "_ZdlPvm": "operator delete",
    "_ZdaPvm": "operator delete",
    "_ZNSt8ios_base4InitC1Ev": "std::ios_base::Init::Init",
    "_ZNSt8ios_base4InitD1Ev": "std::ios_base::Init::~Init",
}
"""Compiler-emitted helpers: allocation, and the iostream setup every C++ program runs.

They are named by mangled symbol like everything else here, because `operator new` is a
name a C program can export too.
"""

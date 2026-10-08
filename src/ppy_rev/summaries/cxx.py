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

IOS_STATE = 0x20
"""`rdstate()` in the `basic_ios` subobject: the bits that say a read failed."""
IOS_FACET = 0xF0
"""The `ctype<char>` a stream widens characters with, which `getline` reads inline."""
IOS_VBASE_OFFSET = -0x18
"""Where the offset to the `basic_ios` subobject sits, before the vtable's entries."""
IOS_SIZE = 0x140
CTYPE_WIDEN_OK = 0x38
"""Nonzero once the widen table is built, which is how inlined code skips the call."""
CTYPE_WIDEN = 0x39
"""A 256-byte table: `widen(c)` for `char` is `c` itself."""
CTYPE_SIZE = 0x140

_STRING = "basic_string"
_ISTREAM = "basic_istream"
_OSTREAM = "basic_ostream"
_IFSTREAM = "basic_ifstream"
_IOS = "9basic_iosI"


def from_symbol(symbol: str) -> str | None:
    """The model name for a mangled libstdc++ symbol, or None when it is not one we know."""
    if not symbol.startswith("_Z"):
        return None
    runtime = _RUNTIME.get(symbol.split("@", 1)[0])
    if runtime is not None:
        return runtime
    if "12__basic_fileI" in symbol and symbol.endswith("7is_openEv"):
        # Optimized code asks the file itself, past the stream it belongs to.
        return "std::ifstream::is_open"
    if _IOS in symbol:
        for part, name in _IOS_MEMBERS.items():
            if symbol.endswith(part):
                return name
        return None
    if _IFSTREAM in symbol:
        for part, name in _IFSTREAM_MEMBERS.items():
            if part in symbol:
                return name
        return None
    if "7getline" in symbol and _STRING in symbol:
        return "std::getline"
    if symbol.startswith("_ZSt") and "rs" in symbol and _ISTREAM in symbol and _STRING in symbol:
        return "std::istream::operator>>"
    if symbol.startswith("_ZNSirsER"):
        # `std::cin >> n`, whose type is the last letter of the mangled name.
        return _NUMBER_EXTRACTIONS.get(symbol.split("@", 1)[0][len("_ZNSirsER") :])
    if symbol.startswith("_ZSt4endl"):
        return "std::endl"
    if _OSTREAM in symbol or symbol.startswith("_ZNSols"):
        return "std::ostream::operator<<"
    if symbol.startswith("_ZNSaI"):
        # `std::allocator<char>`: constructing and destroying one does nothing to memory.
        return "std::allocator"
    if _STRING not in symbol:
        return None
    for suffix, name in _STRING_MEMBERS.items():
        if symbol.endswith(suffix):
            return name
    for part, name in _STRING_INTERNALS.items():
        if part in symbol:
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
    "C1Ev": "std::string::string()",
    "C2Ev": "std::string::string()",
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


_STRING_INTERNALS = {
    "13_M_local_dataEv": "std::string::_M_local_data",
    "7_M_dataEPc": "std::string::_M_data=",
    "7_M_dataEv": "std::string::data",
    "13_M_set_lengthEm": "std::string::_M_set_length",
    "11_M_capacityEm": "std::string::_M_capacity",
    "12_Alloc_hiderC1": "std::string::_M_data=",
    "12_Alloc_hiderC2": "std::string::_M_data=",
    "13_S_copy_chars": "std::string::_S_copy_chars",
    "9_M_createERmm": "std::string::_M_create",
    "EEpLEc": "std::string::operator+=",
    "9push_backEc": "std::string::operator+=",
    "EEaSEPKc": "std::string::operator=",
    "EEaSERKS4_": "std::string::operator=copy",
    "EEaSEOS4_": "std::string::operator=copy",
}
"""The members libstdc++'s own header code calls, which end up in the binary at `-O0`.

`std::string s = "text"` compiles to a chain of these: take the internal buffer, copy
into it, set the length. They are matched by the part of the mangled name that names the
member, because the rest of it is back-references that differ between instantiations.
"""


NUMBER_WIDTHS = {
    "std::istream::operator>>(short)": 2,
    "std::istream::operator>>(int)": 4,
    "std::istream::operator>>(long)": 8,
}
"""How many bytes each numeric extraction stores."""
_NUMBER_EXTRACTIONS = {
    "s": "std::istream::operator>>(short)",
    "t": "std::istream::operator>>(short)",
    "i": "std::istream::operator>>(int)",
    "j": "std::istream::operator>>(int)",
    "l": "std::istream::operator>>(long)",
    "m": "std::istream::operator>>(long)",
    "x": "std::istream::operator>>(long)",
    "y": "std::istream::operator>>(long)",
}
"""`std::istream::operator>>` by the type it reads, from the mangled parameter letter.

Only the integer types: a `float` or a `bool` reads by rules of its own, and guessing
them would put a number in memory that the program never saw.
"""


_IFSTREAM_MEMBERS = {
    "C1EPKc": "std::ifstream::ifstream",
    "C2EPKc": "std::ifstream::ifstream",
    "C1ERKNS": "std::ifstream::ifstream",
    "4openEPKc": "std::ifstream::ifstream",
    "7is_openEv": "std::ifstream::is_open",
    "5closeEv": "std::ifstream::close",
    "D1Ev": "std::ifstream::close",
    "D2Ev": "std::ifstream::close",
}
"""`std::ifstream`, which a challenge reads its flag file with.

Opening one is opening a file; the object then stands in for the stream it is, so
`std::getline(file, line)` reads from that file rather than from the terminal.
"""


_IOS_MEMBERS = {
    "4failEv": "std::ios::fail",
    "3badEv": "std::ios::fail",
    "4goodEv": "std::ios::good",
    "cvbEv": "std::ios::good",
    "ntEv": "std::ios::fail",
    "3eofEv": "std::ios::eof",
}
"""What a program asks a stream about itself.

A file this opens always opened, and its contents are an input, so failure is not a state
any of these report; only `eof` depends on how far the program has read.
"""

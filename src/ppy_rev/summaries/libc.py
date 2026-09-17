"""What ppy-rev knows about C library functions, independent of how they are executed."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ppy_rev.abi import CallingConvention
from ppy_rev.summaries.ctype import CLASSIFIERS


@dataclass(frozen=True, slots=True)
class LibraryFunction:
    name: str
    parameters: int
    """Integer parameters passed in registers (variadic functions: the fixed ones)."""
    variadic: bool = False
    no_return: bool = False


FUNCTIONS: dict[str, LibraryFunction] = {
    function.name: function
    for function in (
        LibraryFunction("strlen", 1),
        LibraryFunction("strcmp", 2),
        LibraryFunction("strncmp", 3),
        LibraryFunction("memcmp", 3),
        LibraryFunction("memcpy", 3),
        LibraryFunction("memmove", 3),
        LibraryFunction("memset", 3),
        LibraryFunction("strcpy", 2),
        LibraryFunction("strncpy", 3),
        LibraryFunction("strcspn", 2),
        LibraryFunction("read", 3),
        LibraryFunction("fgets", 3),
        LibraryFunction("gets", 1),
        LibraryFunction("getchar", 0),
        LibraryFunction("puts", 1),
        LibraryFunction("putchar", 1),
        LibraryFunction("fputs", 2),
        LibraryFunction("fflush", 1),
        LibraryFunction("setbuf", 2),
        LibraryFunction("setvbuf", 4),
        LibraryFunction("printf", 1, variadic=True),
        LibraryFunction("__printf_chk", 2, variadic=True),
        LibraryFunction("exit", 1, no_return=True),
        LibraryFunction("_exit", 1, no_return=True),
        LibraryFunction("abort", 0, no_return=True),
        LibraryFunction("__stack_chk_fail", 0, no_return=True),
        LibraryFunction("malloc", 1),
        LibraryFunction("calloc", 2),
        LibraryFunction("free", 1),
        LibraryFunction("atoi", 1),
        LibraryFunction("atol", 1),
        LibraryFunction("atoll", 1),
        LibraryFunction("strtol", 3),
        LibraryFunction("strtoll", 3),
        LibraryFunction("scanf", 1, variadic=True),
        LibraryFunction("toupper", 1),
        LibraryFunction("tolower", 1),
        LibraryFunction("__ctype_b_loc", 0),
        LibraryFunction("__ctype_toupper_loc", 0),
        LibraryFunction("__ctype_tolower_loc", 0),
        *(LibraryFunction(name, 1) for name in CLASSIFIERS),
    )
}

ALIASES = {
    "__memcpy_chk": "memcpy",
    "__memmove_chk": "memmove",
    "__memset_chk": "memset",
    "__strcpy_chk": "strcpy",
    "__read_chk": "read",
    "__isoc99_scanf": "scanf",
    "__isoc23_scanf": "scanf",
    "__isoc23_strtol": "strtol",
    "__isoc23_strtoll": "strtoll",
}
"""Fortified and standard-revision variants whose leading parameters match the plain
function exactly (and whose behaviour does too, for what the models support)."""


def modeled_reads(convention: CallingConvention) -> Callable[[str], frozenset[str] | None]:
    """The registers ppy-rev's models of library functions actually read."""

    def reads(name: str) -> frozenset[str] | None:
        function = library_function(name)
        if function is None:
            return None
        # The stack pointer is always read: returning pops the return address.
        used = {convention.stack_pointer, *convention.integer_parameters[: function.parameters]}
        if function.variadic:
            used.update(convention.integer_parameters)
        return frozenset(used)

    return reads


def canonical_name(name: str) -> str:
    base = name.split("@", 1)[0]
    return ALIASES.get(base, base)


def library_function(name: str) -> LibraryFunction | None:
    return FUNCTIONS.get(canonical_name(name))

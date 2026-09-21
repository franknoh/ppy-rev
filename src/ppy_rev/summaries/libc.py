"""What ppy-rev knows about C library functions, independent of how they are executed."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ppy_rev.abi import CallingConvention
from ppy_rev.ir.model import ExternalFunction
from ppy_rev.summaries import cxx
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
        LibraryFunction("strnlen", 2),
        LibraryFunction("getuid", 0),
        LibraryFunction("geteuid", 0),
        LibraryFunction("getgid", 0),
        LibraryFunction("getegid", 0),
        LibraryFunction("getpid", 0),
        LibraryFunction("time", 1),
        LibraryFunction("sleep", 1),
        LibraryFunction("usleep", 1),
        LibraryFunction("alarm", 1),
        LibraryFunction("signal", 2),
        LibraryFunction("getppid", 0),
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
        LibraryFunction("write", 3),
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
        LibraryFunction("srand", 1),
        LibraryFunction("rand", 0),
        LibraryFunction("malloc", 1),
        LibraryFunction("calloc", 2),
        LibraryFunction("free", 1),
        LibraryFunction("operator new", 1),
        LibraryFunction("operator delete", 1),
        LibraryFunction("std::ios_base::Init::Init", 0),
        LibraryFunction("std::ios_base::Init::~Init", 0),
        LibraryFunction("__cxa_atexit", 3),
        LibraryFunction("__cxa_guard_acquire", 1),
        LibraryFunction("__cxa_guard_release", 1),
        LibraryFunction("__cxa_guard_abort", 1),
        LibraryFunction("atoi", 1),
        LibraryFunction("atol", 1),
        LibraryFunction("atoll", 1),
        LibraryFunction("strtol", 3),
        LibraryFunction("strtoll", 3),
        LibraryFunction("scanf", 1, variadic=True),
        LibraryFunction("sscanf", 2, variadic=True),
        LibraryFunction("fscanf", 2, variadic=True),
        LibraryFunction("toupper", 1),
        LibraryFunction("tolower", 1),
        LibraryFunction("strchr", 2),
        LibraryFunction("memchr", 3),
        LibraryFunction("std::getline", 2),
        LibraryFunction("std::istream::operator>>(short)", 2),
        LibraryFunction("std::istream::operator>>(int)", 2),
        LibraryFunction("std::istream::operator>>(long)", 2),
        LibraryFunction("std::ostream::operator<<", 2),
        LibraryFunction("std::allocator", 1),
        LibraryFunction("std::string::string", 2),
        LibraryFunction("std::string::string()", 1),
        LibraryFunction("std::string::_M_local_data", 1),
        LibraryFunction("std::string::_M_data=", 2),
        LibraryFunction("std::string::_M_set_length", 2),
        LibraryFunction("std::string::_M_capacity", 2),
        LibraryFunction("std::string::_S_copy_chars", 3),
        LibraryFunction("std::string::_M_create", 3),
        LibraryFunction("std::string::operator+=", 2),
        LibraryFunction("std::string::operator=", 2),
        LibraryFunction("std::string::operator=copy", 2),
        LibraryFunction("std::string::~string", 1),
        LibraryFunction("std::string::size", 1),
        LibraryFunction("std::string::data", 1),
        LibraryFunction("std::string::empty", 1),
        LibraryFunction("std::string::at", 2),
        LibraryFunction("std::istream::operator>>", 2),
        LibraryFunction("std::endl", 1),
        LibraryFunction("fopen", 2),
        LibraryFunction("fclose", 1),
        LibraryFunction("feof", 1),
        LibraryFunction("fread", 4),
        LibraryFunction("fseek", 3),
        LibraryFunction("ftell", 1),
        LibraryFunction("rewind", 1),
        LibraryFunction("fgetc", 1),
        LibraryFunction("fputc", 2),
        LibraryFunction("fwrite", 4),
        LibraryFunction("strcat", 2),
        LibraryFunction("strncat", 3),
        LibraryFunction("strstr", 2),
        LibraryFunction("std::string::begin", 1),
        LibraryFunction("std::string::end", 1),
        LibraryFunction("ptrace", 4, variadic=True),
        LibraryFunction("__errno_location", 0),
        LibraryFunction("__ctype_b_loc", 0),
        LibraryFunction("__ctype_toupper_loc", 0),
        LibraryFunction("__ctype_tolower_loc", 0),
        *(LibraryFunction(name, 1) for name in CLASSIFIERS),
    )
}

ALIASES = {
    "bcmp": "memcmp",  # only zero or nonzero is promised, which memcmp also gives
    "getc": "fgetc",
    "putc": "fputc",
    "__memcpy_chk": "memcpy",
    "__memmove_chk": "memmove",
    "__memset_chk": "memset",
    "__strcpy_chk": "strcpy",
    "__read_chk": "read",
    "__isoc99_scanf": "scanf",
    "__isoc99_fscanf": "fscanf",
    "__isoc99_sscanf": "sscanf",
    "operator.new": "operator new",
    "operator.delete": "operator delete",
    "__cxa_finalize": "__cxa_atexit",
    "bsd_signal": "signal",
    "__sysv_signal": "signal",
    "srandom": "srand",
    "random": "rand",
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


def model_name(external: ExternalFunction) -> str:
    """What the models call an import: C++ by its mangled symbol, C by its name."""
    return cxx.from_symbol(external.symbol) or canonical_name(external.name)


def library_function(name: str) -> LibraryFunction | None:
    return FUNCTIONS.get(canonical_name(name))

"""Symbolic models of C library functions.

Strings are bytes with NUL terminators. Where a string's end depends on symbolic bytes,
results are exact if-then-else chains over the possible terminator positions, bounded by
the first concrete terminator. Pointers, sizes, and descriptors must be determined by the
path condition; otherwise the call stops exploration as unsupported rather than guessing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from functools import partial

from ppy_rev.abi import CallingConvention
from ppy_rev.execution.memory import MemoryFaultError
from ppy_rev.execution.program import (
    CTYPE_POINTERS,
    CXX_CTYPE,
    CXX_IOS_VTABLE,
    ERRNO_ADDRESS,
    FILE_HANDLE_STEP,
    FILE_HANDLES,
    HEAP_SIZE,
    HEAP_START,
    PROCESS_IDS,
    STANDARD_STREAMS,
)
from ppy_rev.ir.model import Origin
from ppy_rev.ir.semantics import to_signed
from ppy_rev.solver.backend import Status
from ppy_rev.summaries import ctype, cxx, formatting, glibc_random, scanning
from ppy_rev.summaries.libc import canonical_name
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.bounds import unsigned_bounds
from ppy_rev.symbolic.evaluate import evaluate
from ppy_rev.symbolic.executor import (
    Executor,
    Exited,
    ExternalOutcome,
    Failed,
    Returned,
    StopReason,
)
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.inputs import file_symbols
from ppy_rev.symbolic.state import ConstraintKind, OpenFile, State

_NEWLINE = sx.const(0x0A, 8)
_ZERO_BYTE = sx.const(0, 8)
_PTRACE_TRACEME = 0
_TRACED = sx.const(0xFFFF_FFFF_FFFF_FFFF, 64)
TRACED_SYMBOL = "__traced"
CLOCK_SYMBOL = "__clock"
_LATEST_CLOCK = 4_102_444_800
"""2100-01-01: past any second a challenge was written to be run in."""
"""The environment value `ptrace(PTRACE_TRACEME)` returns: 0, or -1 under a debugger."""


class _Unsupported(Exception):  # noqa: N818 - internal control flow
    pass


class _Fault(Exception):  # noqa: N818 - internal control flow
    pass


@dataclass(frozen=True, slots=True)
class _Call:
    executor: Executor
    state: State
    arguments: list[Expr]
    registers: dict[str, Expr]
    origin: Origin
    name: str


type _Model = Callable[[_Call], list[ExternalOutcome]]


class SymbolicLibc:
    """`ExternalModels` for the symbolic executor."""

    def __init__(
        self, convention: CallingConvention, string_limit: int = 4096, file_length: int = 64
    ) -> None:
        self.convention = convention
        self.string_limit = string_limit
        self.file_length = file_length
        """Bytes offered for a file the program opens that the analysis did not foresee."""
        self._models: dict[str, _Model] = {
            "strlen": self._strlen,
            "strnlen": self._strnlen,
            "sscanf": self._sscanf,
            "write": self._write_descriptor,
            **{name: partial(self._process_id, name=name) for name in PROCESS_IDS},
            "strcmp": self._strcmp,
            "strncmp": self._strncmp,
            "memcmp": self._memcmp,
            "memcpy": self._memcpy,
            "memmove": self._memmove,
            "memset": self._memset,
            "strcpy": self._strcpy,
            "strncpy": self._strncpy,
            "strcspn": self._strcspn,
            "strchr": self._strchr,
            "memchr": self._memchr,
            "std::getline": self._getline,
            "std::ifstream::ifstream": self._ifstream_open,
            "std::ifstream::is_open": self._ifstream_is_open,
            "std::ifstream::close": self._ifstream_close,
            "std::ios::fail": self._returns_zero,
            "std::ios::good": lambda call: self._returns(call, sx.const(1, 64)),
            "std::ios::eof": self._ios_eof,
            "std::allocator": lambda call: self._returns(call, call.arguments[0]),
            "std::string::string": self._string_new,
            "std::string::string()": self._string_empty_new,
            "std::string::_M_local_data": self._string_local_data,
            "std::string::_M_data=": self._string_set_data,
            "std::string::_M_set_length": self._string_set_length,
            "std::string::_M_capacity": self._string_set_capacity,
            "std::string::_S_copy_chars": self._string_copy_chars,
            "std::string::_M_create": self._string_create,
            "std::string::operator+=": self._string_append,
            "std::string::operator=": self._string_assign,
            "std::string::operator=copy": self._string_assign_copy,
            "std::string::~string": self._returns_zero,
            "std::string::size": self._string_size,
            "std::string::data": self._string_data,
            "std::string::empty": self._string_empty,
            "std::ostream::operator<<": self._ostream_write,
            "std::string::at": self._string_at,
            "std::istream::operator>>": self._istream_read,
            **{
                name: partial(self._istream_number, width=width)
                for name, width in cxx.NUMBER_WIDTHS.items()
            },
            "std::endl": self._endl,
            "std::string::begin": self._string_data,
            "std::string::end": self._string_end,
            "read": self._read,
            "fgets": self._fgets,
            "fopen": self._fopen,
            "fclose": self._returns_zero,
            "feof": self._feof,
            "fread": self._fread,
            "fgetc": self._fgetc,
            "fputc": self._fputc,
            "fwrite": self._fwrite,
            "strcat": lambda call: self._concatenate(call, None),
            "strncat": lambda call: self._concatenate(
                call, self._concrete(call, call.arguments[2], "limit")
            ),
            "strstr": self._strstr,
            "fseek": self._fseek,
            "ftell": self._ftell,
            "rewind": self._rewind,
            "gets": self._gets,
            "srand": self._srand,
            "time": self._time,
            "sleep": self._returns_zero,
            "usleep": self._returns_zero,
            "alarm": self._returns_zero,
            "signal": self._returns_zero,
            "close": self._returns_zero,
            "unlink": self._returns_zero,
            "sigemptyset": self._returns_zero,
            "getenv": self._returns_zero,
            "access": lambda call: self._returns(call, sx.const((1 << 64) - 1, 64)),
            "fileno": self._fileno,
            "rand": self._rand,
            "getchar": self._getchar,
            "puts": self._puts,
            "putchar": self._putchar,
            "fputs": self._fputs,
            "printf": self._printf,
            "sprintf": self._sprintf,
            "snprintf": self._snprintf,
            "__printf_chk": self._printf,
            "fflush": self._returns_zero,
            "setbuf": self._returns_zero,
            "setvbuf": self._returns_zero,
            "free": self._returns_zero,
            "exit": self._exit,
            "_exit": self._exit,
            "abort": self._abort,
            "__stack_chk_fail": self._abort,
            "malloc": self._malloc,
            "__errno_location": lambda call: self._returns(call, sx.const(ERRNO_ADDRESS, 64)),
            "ptrace": self._ptrace,
            "calloc": self._calloc,
            "operator new": self._malloc,
            "operator delete": self._returns_zero,
            "std::ios_base::Init::Init": self._returns_zero,
            "std::ios_base::Init::~Init": self._returns_zero,
            "__cxa_atexit": self._returns_zero,
            "__cxa_guard_acquire": self._guard_acquire,
            "__cxa_guard_release": self._guard_release,
            "__cxa_guard_abort": self._returns_zero,
            "atoi": self._atoi,
            "atol": self._atol,
            "atoll": self._atol,
            "strtol": self._strtol,
            "strtoll": self._strtol,
            "strtoul": self._strtol,
            "strtoull": self._strtol,
            "scanf": self._scanf,
            "fscanf": self._fscanf,
            "toupper": lambda call: self._case(call, 0x61, 0x7A, -0x20),
            "tolower": lambda call: self._case(call, 0x41, 0x5A, 0x20),
            **{
                name: lambda call, pointer=pointer: self._returns(call, sx.const(pointer, 64))
                for name, pointer in CTYPE_POINTERS.items()
            },
            **{
                name: lambda call, flag=flag: self._classify(call, flag)
                for name, flag in ctype.CLASSIFIERS.items()
            },
        }

    def call(
        self,
        executor: Executor,
        state: State,
        name: str,
        arguments: dict[str, Expr],
        origin: Origin,
    ) -> list[ExternalOutcome] | None:
        model = self._models.get(canonical_name(name))
        if model is None:
            return None
        values = [
            arguments.get(register, sx.const(0, 64))
            for register in self.convention.integer_parameters
        ]
        context = _Call(executor, state, values, arguments, origin, canonical_name(name))
        try:
            return model(context)
        except _Unsupported as problem:
            return [Failed(state, StopReason.UNSUPPORTED, f"{name}: {problem}")]
        except _Fault as problem:
            return [Failed(state, StopReason.FAULT, f"{name}: {problem}")]

    # -- helpers ---------------------------------------------------------------------------

    def _outputs(self, call: _Call, value: Expr) -> dict[str, Expr]:
        outputs = dict(call.registers)
        result_register = self.convention.integer_returns[0]
        outputs[result_register] = value if value.width == 64 else sx.zero_extend(value, 64)
        return outputs

    def _returns(self, call: _Call, value: Expr) -> list[ExternalOutcome]:
        return [Returned(call.state, self._outputs(call, value))]

    def _returns_zero(self, call: _Call) -> list[ExternalOutcome]:
        return self._returns(call, sx.const(0, 64))

    def _fileno(self, call: _Call) -> list[ExternalOutcome]:
        """`fileno(stream)`: the descriptor behind a standard stream, else a generic one."""
        stream = self._concrete(call, call.arguments[0], "stream")
        fds = {
            STANDARD_STREAMS["stdin"]: 0,
            STANDARD_STREAMS["stdout"]: 1,
            STANDARD_STREAMS["stderr"]: 2,
        }
        return self._returns(call, sx.const(fds.get(stream, 3), 64))

    @staticmethod
    def _concrete(call: _Call, value: Expr, what: str) -> int:
        known = call.executor.unique_value(call.state, value)
        if known is None:
            raise _Unsupported(f"{what} is symbolic ({sx.render(value, 80)})")
        return known

    @staticmethod
    def _byte(call: _Call, address: int) -> Expr:
        if not call.state.memory.accessible(address, 1, write=False):
            raise _Fault(f"read of unmapped memory at {address:#x}")
        return call.state.memory.read_byte(address)

    @staticmethod
    def _write(call: _Call, address: int, value: Expr) -> None:
        if not call.state.memory.accessible(address, 1, write=True):
            raise _Fault(f"write to unwritable memory at {address:#x}")
        call.state.memory.write_byte(address, value)

    def _string_bytes(self, call: _Call, address: int) -> list[Expr]:
        """Bytes up to (not including) the first concrete NUL; earlier bytes may be NUL too."""
        result: list[Expr] = []
        for index in range(self.string_limit):
            byte = self._byte(call, address + index)
            if byte.is_const and byte.value == 0:
                return result
            result.append(byte)
        raise _Unsupported(f"no terminator within {self.string_limit} bytes of {address:#x}")

    @staticmethod
    def _difference(left: Expr, right: Expr) -> Expr:
        return sx.sub(sx.zero_extend(left, 32), sx.zero_extend(right, 32))

    # -- strings ---------------------------------------------------------------------------

    def _strlen(self, call: _Call) -> list[ExternalOutcome]:
        text = self._string_bytes(call, self._concrete(call, call.arguments[0], "string"))
        length = sx.const(len(text), 64)
        for index in reversed(range(len(text))):
            byte = text[index]
            if not byte.is_const:
                length = sx.ite(sx.equal(byte, _ZERO_BYTE), sx.const(index, 64), length)
        return self._returns(call, length)

    def _strnlen(self, call: _Call) -> list[ExternalOutcome]:
        """`strnlen(s, n)`: the length, but never more than `n`."""
        limit = self._concrete(call, call.arguments[1], "limit")
        address = self._concrete(call, call.arguments[0], "string")
        text = self._string_bytes(call, address)[:limit]
        length = sx.const(len(text), 64)
        for index in reversed(range(len(text))):
            byte = text[index]
            if not byte.is_const:
                length = sx.ite(sx.equal(byte, _ZERO_BYTE), sx.const(index, 64), length)
        return self._returns(call, length)

    def _process_id(self, call: _Call, name: str) -> list[ExternalOutcome]:
        """What the process says it is: settled, and the same in both engines."""
        return self._returns(call, sx.const(PROCESS_IDS[name], 64))

    def _write_descriptor(self, call: _Call) -> list[ExternalOutcome]:
        """`write(fd, buffer, count)` to stdout or stderr; another descriptor has no model."""
        descriptor = self._concrete(call, sx.extract(call.arguments[0], 0, 32), "descriptor")
        if descriptor not in (1, 2):
            raise _Unsupported(f"write to file descriptor {descriptor}")
        buffer = self._concrete(call, call.arguments[1], "buffer")
        count = self._concrete(call, call.arguments[2], "count")
        call.state.io.stdout.extend(self._byte(call, buffer + index) for index in range(count))
        return self._returns(call, sx.const(count, 64))

    def _compare_strings(self, call: _Call, limit: int | None) -> Expr:
        left_address = self._concrete(call, call.arguments[0], "first string")
        right_address = self._concrete(call, call.arguments[1], "second string")
        pairs: list[tuple[Expr, Expr]] = []
        result = sx.const(0, 32)
        bound = self.string_limit if limit is None else min(limit, self.string_limit)
        for index in range(bound):
            left = self._byte(call, left_address + index)
            right = self._byte(call, right_address + index)
            if left.is_const and right.is_const and (left.value != right.value or left.value == 0):
                result = sx.const(
                    (left.value - right.value) & 0xFFFFFFFF if left.value != right.value else 0, 32
                )
                break
            pairs.append((left, right))
        else:
            if limit is None or limit > self.string_limit:
                raise _Unsupported(f"strings compare equal beyond {self.string_limit} bytes")
        for left, right in reversed(pairs):
            differs = sx.bool_not(sx.equal(left, right))
            ended = sx.equal(left, _ZERO_BYTE)
            result = sx.ite(
                differs, self._difference(left, right), sx.ite(ended, sx.const(0, 32), result)
            )
        return result

    def _strcmp(self, call: _Call) -> list[ExternalOutcome]:
        return self._returns(call, self._compare_strings(call, None))

    def _strncmp(self, call: _Call) -> list[ExternalOutcome]:
        limit = self._concrete(call, call.arguments[2], "length")
        return self._returns(call, self._compare_strings(call, limit))

    def _memcmp(self, call: _Call) -> list[ExternalOutcome]:
        left_address = self._concrete(call, call.arguments[0], "first buffer")
        right_address = self._concrete(call, call.arguments[1], "second buffer")
        size = self._concrete(call, call.arguments[2], "size")
        if size > self.string_limit:
            raise _Unsupported(f"memcmp of {size} bytes")
        result = sx.const(0, 32)
        for index in reversed(range(size)):
            left = self._byte(call, left_address + index)
            right = self._byte(call, right_address + index)
            result = sx.ite(
                sx.bool_not(sx.equal(left, right)), self._difference(left, right), result
            )
        return self._returns(call, result)

    def _copy(self, call: _Call, destination: int, source: int, size: int) -> None:
        values = [self._byte(call, source + index) for index in range(size)]
        for index, value in enumerate(values):
            self._write(call, destination + index, value)

    def _memcpy(self, call: _Call) -> list[ExternalOutcome]:
        """`memcpy(dst, src, n)`, where `n` may be a length the input decides.

        Optimized C++ copies a string that way. Each byte is then written only where it
        is really part of the copy, for as far as the size can reach.
        """
        destination = self._concrete(call, call.arguments[0], "destination")
        source = self._concrete(call, call.arguments[1], "source")
        size = call.executor.unique_value(call.state, call.arguments[2])
        if size is None:
            count = call.arguments[2]
            for offset in range(self._length_bound(call, count, "size")):
                copied = sx.unsigned_less(sx.const(offset, 64), count)
                if copied is sx.FALSE:
                    continue
                old_byte = self._byte(call, destination + offset)
                self._write(
                    call,
                    destination + offset,
                    sx.ite(copied, self._byte(call, source + offset), old_byte),
                )
            return self._returns(call, sx.const(destination, 64))
        if size > 1 << 20:
            raise _Unsupported(f"copy of {size} bytes")
        self._copy(call, destination, source, size)
        return self._returns(call, sx.const(destination, 64))

    def _memmove(self, call: _Call) -> list[ExternalOutcome]:
        return self._memcpy(call)  # bytes are read before any is written

    def _memset(self, call: _Call) -> list[ExternalOutcome]:
        destination = self._concrete(call, call.arguments[0], "destination")
        size = self._concrete(call, call.arguments[2], "size")
        if size > 1 << 20:
            raise _Unsupported(f"memset of {size} bytes")
        byte = sx.extract(call.arguments[1], 0, 8)
        for index in range(size):
            self._write(call, destination + index, byte)
        return self._returns(call, sx.const(destination, 64))

    def _strcpy(self, call: _Call) -> list[ExternalOutcome]:
        destination = self._concrete(call, call.arguments[0], "destination")
        source = self._concrete(call, call.arguments[1], "source")
        text = self._string_bytes(call, source)
        copying = sx.TRUE
        for index, byte in enumerate([*text, _ZERO_BYTE]):
            old = self._byte(call, destination + index)
            self._write(call, destination + index, sx.ite(copying, byte, old))
            copying = sx.bool_and(copying, sx.bool_not(sx.equal(byte, _ZERO_BYTE)))
        return self._returns(call, sx.const(destination, 64))

    def _strncpy(self, call: _Call) -> list[ExternalOutcome]:
        destination = self._concrete(call, call.arguments[0], "destination")
        source = self._concrete(call, call.arguments[1], "source")
        size = self._concrete(call, call.arguments[2], "size")
        if size > 1 << 20:
            raise _Unsupported(f"strncpy of {size} bytes")
        # Source bytes are read only up to a terminator that is certainly there.
        text: list[Expr] = []
        while len(text) < size:
            byte = self._byte(call, source + len(text))
            if byte.is_const and byte.value == 0:
                break
            text.append(byte)
        copying = sx.TRUE
        for index in range(size):
            byte = text[index] if index < len(text) else _ZERO_BYTE
            self._write(call, destination + index, sx.ite(copying, byte, _ZERO_BYTE))
            copying = sx.bool_and(copying, sx.bool_not(sx.equal(byte, _ZERO_BYTE)))
        return self._returns(call, sx.const(destination, 64))

    # -- the C++ standard library ----------------------------------------------------------

    def _string_new(self, call: _Call) -> list[ExternalOutcome]:
        """`std::string s;` or `std::string s(text)`: an object holding what it is given."""
        object_at = self._concrete(call, call.arguments[0], "string")
        source = call.executor.unique_value(call.state, call.arguments[1])
        bytes_ = self._string_bytes(call, source) if source else []
        self._store_string(call, call.state, object_at, bytes_)
        return self._returns(call, sx.const(object_at, 64))

    def _string_empty_new(self, call: _Call) -> list[ExternalOutcome]:
        """`std::string s;`: an empty object, whatever the registers happen to hold."""
        object_at = self._concrete(call, call.arguments[0], "string")
        self._store_string(call, call.state, object_at, [])
        return self._returns(call, sx.const(object_at, 64))

    def _store_string(
        self,
        call: _Call,
        state: State,
        object_at: int,
        content: list[Expr],
        size: Expr | None = None,
        in_object: bool | None = None,
    ) -> None:
        """Write `content` into a `std::string`, laid out as libstdc++ lays it out.

        `size` may be symbolic — a line whose length the input decides — in which case the
        bytes past it are the terminator, as they are in the real thing. `in_object` says
        which buffer holds them; by default the one libstdc++ would use for this length.
        """
        length = sx.const(len(content), 64) if size is None else size
        if in_object is None:
            in_object = len(content) <= cxx.SMALL
        if in_object:
            buffer = object_at + cxx.BUFFER
        else:
            buffer = self._allocate(call, len(content) + 1)
            if not buffer:
                raise _Unsupported("a std::string longer than the heap can hold")
            self._store(call, state, object_at + cxx.CAPACITY, sx.const(len(content), 64))
        self._store(call, state, object_at + cxx.DATA, sx.const(buffer, 64))
        self._store(call, state, object_at + cxx.SIZE, length)
        for index, byte in enumerate(content):
            position = sx.const(index, 64)
            self._write_to(
                state, buffer + index, sx.ite(sx.unsigned_less(position, length), byte, _ZERO_BYTE)
            )
        self._write_to(state, buffer + len(content), _ZERO_BYTE)

    @staticmethod
    def _store(call: _Call, state: State, address: int, value: Expr) -> None:
        del call
        if not state.memory.accessible(address, value.width // 8, write=True):
            raise _Fault(f"write to unwritable memory at {address:#x}")
        state.memory.store(address, value)

    @staticmethod
    def _write_to(state: State, address: int, value: Expr) -> None:
        if not state.memory.accessible(address, 1, write=True):
            raise _Fault(f"write to unwritable memory at {address:#x}")
        state.memory.write_byte(address, value)

    def _string_local_data(self, call: _Call) -> list[ExternalOutcome]:
        """`_M_local_data()`: the buffer inside the object, where a short string lives."""
        object_at = self._concrete(call, call.arguments[0], "string")
        return self._returns(call, sx.const(object_at + cxx.BUFFER, 64))

    def _string_set_data(self, call: _Call) -> list[ExternalOutcome]:
        """`_M_data(p)`, and the `_Alloc_hider` constructor that is the same store."""
        object_at = self._concrete(call, call.arguments[0], "string")
        self._store(call, call.state, object_at + cxx.DATA, call.arguments[1])
        return self._returns(call, sx.const(object_at, 64))

    def _string_set_length(self, call: _Call) -> list[ExternalOutcome]:
        """`_M_set_length(n)`: the length, and the terminator the string keeps after it.

        A length the input decides is kept as it is; the terminator then goes wherever it
        lands, which is one conditional write per position it could take.
        """
        object_at = self._concrete(call, call.arguments[0], "string")
        length = call.arguments[1]
        self._store(call, call.state, object_at + cxx.SIZE, length)
        data = self._concrete(call, self._string_field(call, cxx.DATA), "string data")
        for offset in range(self._length_bound(call, length, "length") + 1):
            here = sx.equal(length, sx.const(offset, length.width))
            if here is sx.FALSE:
                continue
            old_byte = self._byte(call, data + offset)
            self._write(call, data + offset, sx.ite(here, _ZERO_BYTE, old_byte))
        return self._returns(call, sx.const(object_at, 64))

    def _length_bound(self, call: _Call, length: Expr, what: str) -> int:
        """How long a string can be, for writing one condition per byte it may hold."""
        known = call.executor.unique_value(call.state, length)
        if known is not None:
            return known
        highest = unsigned_bounds(length)[1]
        if highest > self.string_limit:
            raise _Unsupported(f"{what} is symbolic ({sx.render(length, 80)})")
        return highest

    def _string_set_capacity(self, call: _Call) -> list[ExternalOutcome]:
        object_at = self._concrete(call, call.arguments[0], "string")
        self._store(call, call.state, object_at + cxx.CAPACITY, call.arguments[1])
        return self._returns(call, sx.const(object_at, 64))

    def _string_copy_chars(self, call: _Call) -> list[ExternalOutcome]:
        """`_S_copy_chars(destination, first, last)`: the copy a construction ends with.

        How much is copied may be up to the input, in which case each byte is written
        only where it is really part of the string.
        """
        destination = self._concrete(call, call.arguments[0], "destination")
        first = self._concrete(call, call.arguments[1], "source")
        count = sx.sub(call.arguments[2], sx.const(first, 64))
        for offset in range(self._length_bound(call, count, "end of source")):
            copied = sx.unsigned_less(sx.const(offset, 64), count)
            if copied is sx.FALSE:
                continue
            old_byte = self._byte(call, destination + offset)
            self._write(
                call,
                destination + offset,
                sx.ite(copied, self._byte(call, first + offset), old_byte),
            )
        return self._returns(call, sx.const(destination, 64))

    def _string_create(self, call: _Call) -> list[ExternalOutcome]:
        """`_M_create(capacity, old)`: a buffer for a string too long to live in the object.

        A capacity the input decides gets the largest buffer it could ask for, which is
        the one the real allocation would have to cover for that input.
        """
        capacity_at = self._concrete(call, call.arguments[1], "capacity")
        wanted = call.state.memory.load(capacity_at, 64)
        buffer = self._allocate(call, self._length_bound(call, wanted, "capacity") + 1)
        if not buffer:
            raise _Unsupported("a std::string longer than the heap can hold")
        return self._returns(call, sx.const(buffer, 64))

    def _string_append(self, call: _Call) -> list[ExternalOutcome]:
        """`s += c`: one character onto the end, moving to the heap if it no longer fits.

        Where the end is has to be known: a string whose length the input decides would
        put the character in a place the analysis cannot name.
        """
        object_at = self._concrete(call, call.arguments[0], "string")
        data = self._concrete(call, self._string_field(call, cxx.DATA), "string data")
        length = self._concrete(call, self._string_field(call, cxx.SIZE), "string length")
        content = [self._byte(call, data + offset) for offset in range(length)]
        character = sx.extract(call.arguments[1], 0, 8)
        self._store_string(call, call.state, object_at, [*content, character])
        return self._returns(call, sx.const(object_at, 64))

    def _string_assign(self, call: _Call) -> list[ExternalOutcome]:
        """`s = "text"`: the object holds what the C string holds."""
        object_at = self._concrete(call, call.arguments[0], "string")
        source = self._concrete(call, call.arguments[1], "text")
        self._store_string(call, call.state, object_at, self._string_bytes(call, source))
        return self._returns(call, sx.const(object_at, 64))

    def _string_assign_copy(self, call: _Call) -> list[ExternalOutcome]:
        """`s = other`: the same bytes in a second object."""
        object_at = self._concrete(call, call.arguments[0], "string")
        other = self._concrete(call, call.arguments[1], "string")
        data = self._concrete(call, call.state.memory.load(other + cxx.DATA, 64), "string data")
        length = self._concrete(call, call.state.memory.load(other + cxx.SIZE, 64), "string length")
        content = [self._byte(call, data + offset) for offset in range(length)]
        self._store_string(call, call.state, object_at, content)
        return self._returns(call, sx.const(object_at, 64))

    def _string_field(self, call: _Call, offset: int) -> Expr:
        object_at = self._concrete(call, call.arguments[0], "string")
        address = object_at + offset
        if not call.state.memory.accessible(address, 8, write=False):
            raise _Fault(f"read of unmapped memory at {address:#x}")
        return call.state.memory.load(address, 64)

    def _string_size(self, call: _Call) -> list[ExternalOutcome]:
        return self._returns(call, self._string_field(call, cxx.SIZE))

    def _string_data(self, call: _Call) -> list[ExternalOutcome]:
        return self._returns(call, self._string_field(call, cxx.DATA))

    def _string_at(self, call: _Call) -> list[ExternalOutcome]:
        """`s[i]` and `s.at(i)`: the address of a character, which the caller then reads."""
        data = self._string_field(call, cxx.DATA)
        index = call.arguments[1]
        return self._returns(call, sx.add(data, index))

    def _string_end(self, call: _Call) -> list[ExternalOutcome]:
        data = self._string_field(call, cxx.DATA)
        return self._returns(call, sx.add(data, self._string_field(call, cxx.SIZE)))

    def _string_empty(self, call: _Call) -> list[ExternalOutcome]:
        size = self._string_field(call, cxx.SIZE)
        return self._returns(call, sx.flag(sx.equal(size, sx.const(0, 64)), 64))

    def _ostream_write(self, call: _Call) -> list[ExternalOutcome]:
        """`out << text`: what it prints matters only as output, so only that is modeled."""
        stream = call.arguments[0]
        text = call.executor.unique_value(call.state, call.arguments[1])
        if text is not None and call.state.memory.accessible(text, 1, write=False):
            call.state.io.stdout.extend(self._string_bytes(call, text))
        return self._returns(call, stream)

    def _endl(self, call: _Call) -> list[ExternalOutcome]:
        """`out << std::endl`: a newline, and a flush that changes nothing here."""
        call.state.io.stdout.append(_NEWLINE)
        return self._returns(call, call.arguments[0])

    def _istream_read(self, call: _Call) -> list[ExternalOutcome]:
        """`in >> s`: the next whitespace-delimited token, into a std::string."""
        object_at = self._concrete(call, call.arguments[1], "string")
        io = call.state.io
        window = list(io.stdin[io.stdin_position :])
        if not window:
            self._at_end(call)
            return self._returns(call, call.arguments[0])
        options: list[tuple[Expr, tuple[int, int]]] = []
        for skipped in (0, 1):
            if skipped >= len(window):
                break
            lead = sx.TRUE if not skipped else _is_space(window[0])
            token = sx.TRUE
            for length in range(1, len(window) - skipped + 1):
                token = sx.bool_and(token, sx.bool_not(_is_space(window[skipped + length - 1])))
                after = window[skipped + length] if skipped + length < len(window) else None
                ends = sx.TRUE if after is None else _is_space(after)
                options.append((sx.bool_and(lead, sx.bool_and(token, ends)), (skipped, length)))
        options.sort(key=lambda option: option[1])
        outcomes: list[ExternalOutcome] = []
        note = "a token ends at whitespace"
        for state, (skipped, length) in _split(call, call.state, options, note):
            start = state.io.stdin_position + skipped
            content = list(state.io.stdin[start : start + length])
            self._store_string(call, state, object_at, content)
            state.io.stdin_reads.append((start, start + length, False))
            state.io.stdin_position = start + length
            outcomes.append(Returned(state, self._outputs(call, call.arguments[0])))
        return outcomes

    def _istream_number(self, call: _Call, width: int) -> list[ExternalOutcome]:
        """`in >> n`: whitespace, then a number, exactly as `scanf("%d")` reads one."""
        destination = self._concrete(call, call.arguments[1], "number")
        directives = [
            scanning.Directive(scanning.DirectiveKind.SPACE),
            scanning.Directive(scanning.DirectiveKind.DECIMAL, store_size=width),
        ]
        scanner = _Scanner(self, call, directives, [destination], STANDARD_STREAMS["stdin"])
        scanner.result = call.arguments[0]  # the stream, so `in >> a >> b` chains
        return scanner.run()

    def _getline(self, call: _Call) -> list[ExternalOutcome]:
        """`std::getline(in, s)`: a line without its newline, into a std::string.

        `in` is the terminal or a file the program opened; an `ifstream` stands in for
        its own stream, so which it is comes from the object the call is given.
        """
        object_at = self._concrete(call, call.arguments[1], "string")
        stream = self._reading_stream(call)
        content, position = self._stream(call, stream)
        taken = list(content[position:])
        if not taken:
            self._at_end(call, stream)
            return self._returns(call, call.arguments[0])
        # The line ends at the first newline; where that is may be up to the input.
        length = sx.const(len(taken), 64)
        for index in reversed(range(len(taken))):
            length = sx.ite(sx.equal(taken[index], _NEWLINE), sx.const(index, 64), length)
        # libstdc++ keeps a short string in the object and a longer one on the heap, and
        # optimized code reads the object itself, so which it is has to be decided here.
        short = sx.unsigned_less_equal(length, sx.const(cxx.SMALL, 64))
        options = [(short, True), (sx.bool_not(short), False)]
        if len(taken) <= cxx.SMALL:
            options = [(sx.TRUE, True)]
        outcomes: list[ExternalOutcome] = []
        for state, is_short in _split(call, call.state, options, "a std::string holds 15 bytes"):
            kept = taken[: cxx.SMALL] if is_short else taken
            self._store_string(call, state, object_at, kept, length, in_object=is_short)
            item = state.io.files.get(stream)
            if stream == STANDARD_STREAMS["stdin"]:
                state.io.stdin_reads.append((position, position + len(kept), True))
            elif item is not None:
                state.io.line_read.add(item.name)
            consumed = call.executor.unique_value(state, length)
            branch = replace(call, state=state)
            if consumed is None:
                note = "input after a symbolic-length getline is treated as empty"
                if item is not None:
                    # Where the line ends is up to the file, so all of it was looked at.
                    state.io.read_to[item.name] = len(content)
                self._truncate(branch, stream, position, note)
            else:
                self._advance(branch, stream, consumed + (1 if consumed < len(taken) else 0))
            outcomes.append(Returned(state, self._outputs(call, call.arguments[0])))
        return outcomes

    def _reading_stream(self, call: _Call) -> int:
        """Which stream a C++ read is on: a file the program opened, or the terminal."""
        stream = call.executor.unique_value(call.state, call.arguments[0])
        if stream is not None and stream in call.state.io.files:
            return stream
        return STANDARD_STREAMS["stdin"]

    def _ifstream_open(self, call: _Call) -> list[ExternalOutcome]:
        """`std::ifstream file(path)`: the object stands in for the stream it opens."""
        object_at = self._concrete(call, call.arguments[0], "stream")
        path = self._string_bytes(call, self._concrete(call, call.arguments[1], "path"))
        if not path or any(not byte.is_const for byte in path):
            raise _Unsupported("std::ifstream of a path the program computes")
        name = bytes(byte.value for byte in path).decode("latin-1")
        io = call.state.io
        content = io.contents.get(name)
        if content is None:
            content = file_symbols(name, self.file_length)
            io.contents[name] = content
        io.files[object_at] = OpenFile(name, content)
        io.positions[object_at] = 0
        # Optimized code reads the stream through its own vtable, as it does for `cin`.
        self._store(call, call.state, object_at, sx.const(CXX_IOS_VTABLE, 64))
        if call.state.memory.accessible(object_at + cxx.IOS_FACET, 8, write=True):
            self._store(call, call.state, object_at + cxx.IOS_FACET, sx.const(CXX_CTYPE, 64))
        return self._returns(call, sx.const(object_at, 64))

    def _ios_eof(self, call: _Call) -> list[ExternalOutcome]:
        """Whether the program has read everything the stream holds."""
        stream = self._reading_stream(call)
        content, position = self._stream(call, stream)
        return self._returns(call, sx.const(int(position >= len(content)), 64))

    def _ifstream_is_open(self, call: _Call) -> list[ExternalOutcome]:
        """Whether the file opened: it did, since its contents are an input.

        Optimized code asks the file object inside the stream rather than the stream, so
        an address this does not know is still a file the program opened.
        """
        return self._returns(call, sx.const(1, 64))

    def _ifstream_close(self, call: _Call) -> list[ExternalOutcome]:
        stream = call.executor.unique_value(call.state, call.arguments[0])
        if stream is not None:
            call.state.io.positions.pop(stream, None)
        return self._returns_zero(call)

    def _memchr(self, call: _Call) -> list[ExternalOutcome]:
        """`memchr(s, c, n)`: the first `c` in `n` bytes, NULL if there is none."""
        address = self._concrete(call, call.arguments[0], "buffer")
        wanted = sx.extract(call.arguments[1], 0, 8)
        count = self._concrete(call, call.arguments[2], "count")
        result = sx.const(0, 64)
        for index in reversed(range(count)):
            found = sx.equal(self._byte(call, address + index), wanted)
            result = sx.ite(found, sx.const(address + index, 64), result)
        return self._returns(call, result)

    def _strchr(self, call: _Call) -> list[ExternalOutcome]:
        """`strchr(s, c)`: the first `c` in `s`, NULL if there is none.

        A zero byte ends the string, so the scan stops there — and `strchr(s, 0)` returns
        that terminator rather than NULL.
        """
        address = self._concrete(call, call.arguments[0], "string")
        wanted = sx.extract(call.arguments[1], 0, 8)
        text = self._string_bytes(call, address)
        terminator = sx.equal(wanted, _ZERO_BYTE)
        result = sx.ite(terminator, sx.const(address + len(text), 64), sx.const(0, 64))
        for index in reversed(range(len(text))):
            here = sx.const(address + index, 64)
            ends = sx.equal(text[index], _ZERO_BYTE)
            found = sx.equal(text[index], wanted)
            result = sx.ite(
                ends,
                sx.ite(terminator, here, sx.const(0, 64)),
                sx.ite(found, here, result),
            )
        return self._returns(call, result)

    def _strcspn(self, call: _Call) -> list[ExternalOutcome]:
        text = self._string_bytes(call, self._concrete(call, call.arguments[0], "string"))
        rejected = self._string_bytes(call, self._concrete(call, call.arguments[1], "set"))
        if any(not byte.is_const for byte in rejected):
            raise _Unsupported("the rejected set is symbolic")
        stops = [_ZERO_BYTE, *rejected]
        result = sx.const(len(text), 64)
        for index in reversed(range(len(text))):
            byte = text[index]
            stop = sx.bool_or(*(sx.equal(byte, candidate) for candidate in stops))
            result = sx.ite(stop, sx.const(index, 64), result)
        return self._returns(call, result)

    # -- input -----------------------------------------------------------------------------

    def _read(self, call: _Call) -> list[ExternalOutcome]:
        descriptor = self._concrete(call, sx.extract(call.arguments[0], 0, 32), "descriptor")
        if descriptor != 0:
            raise _Unsupported(f"read from file descriptor {descriptor}")
        buffer = self._concrete(call, call.arguments[1], "buffer")
        count = self._concrete(call, call.arguments[2], "count")
        io = call.state.io
        available = io.stdin[io.stdin_position : io.stdin_position + count]
        if not available:
            self._at_end(call)
        for index, byte in enumerate(available):
            self._write(call, buffer + index, byte)
        io.stdin_reads.append((io.stdin_position, io.stdin_position + len(available), False))
        io.stdin_position += len(available)
        return self._returns(call, sx.const(len(available), 64))

    # -- files -----------------------------------------------------------------------------

    def _fopen(self, call: _Call) -> list[ExternalOutcome]:
        """Whatever the program opens is an input: the analysis plans the paths it can read
        statically, and a path it only learns here becomes an input too. A path the program
        computes is refused, since the answer could not name the file it belongs in."""
        path = self._string_bytes(call, self._concrete(call, call.arguments[0], "path"))
        if not path or any(not byte.is_const for byte in path):
            raise _Unsupported("fopen of a path the program computes")
        name = bytes(byte.value for byte in path).decode("latin-1")
        io = call.state.io
        content = io.contents.get(name)
        if content is None:
            content = file_symbols(name, self.file_length)
            io.contents[name] = content
        for handle, item in io.files.items():
            if item.name == name:
                io.positions[handle] = 0
                return self._returns(call, sx.const(handle, 64))
        handle = FILE_HANDLES + FILE_HANDLE_STEP * len(io.files)
        io.files[handle] = OpenFile(name, content)
        io.positions[handle] = 0
        return self._returns(call, sx.const(handle, 64))

    def _stream(self, call: _Call, stream: int) -> tuple[tuple[Expr, ...], int]:
        """What a stream still holds, and how far it has been read."""
        io = call.state.io
        if stream == STANDARD_STREAMS["stdin"]:
            content, position = io.stdin, io.stdin_position
        else:
            item = io.files.get(stream)
            if item is None:
                raise _Unsupported(f"stream {stream:#x} was not opened here")
            content, position = item.content, io.positions.get(stream, 0)
        if position >= len(content):
            self._at_end(call, stream)
        return content, position

    def _advance(self, call: _Call, stream: int, count: int) -> None:
        io = call.state.io
        if stream == STANDARD_STREAMS["stdin"]:
            io.stdin_position += count
            return
        position = io.positions.get(stream, 0) + count
        io.positions[stream] = position
        item = io.files.get(stream)
        if item is not None:
            io.read_to[item.name] = max(io.read_to.get(item.name, 0), position)

    def _feof(self, call: _Call) -> list[ExternalOutcome]:
        stream = self._concrete(call, call.arguments[0], "stream")
        content, position = self._stream(call, stream)
        return self._returns(call, sx.const(int(position >= len(content)), 64))

    def _seek(self, call: _Call, stream: int, offset: int, whence: int) -> int:
        """Move within a stream; the content's length is known, so this stays concrete."""
        content, position = self._stream(call, stream)
        start = {0: 0, 1: position, 2: len(content)}.get(whence)
        if start is None:
            raise _Unsupported(f"fseek with whence {whence}")
        target = max(0, min(len(content), start + offset))
        io = call.state.io
        if stream == STANDARD_STREAMS["stdin"]:
            io.stdin_position = target
        else:
            io.positions[stream] = target
        return target

    def _fseek(self, call: _Call) -> list[ExternalOutcome]:
        stream = self._concrete(call, call.arguments[0], "stream")
        offset = self._concrete(call, call.arguments[1], "offset")
        whence = self._concrete(call, sx.extract(call.arguments[2], 0, 32), "whence")
        self._seek(call, stream, to_signed(offset, 64), whence)
        return self._returns_zero(call)

    def _ftell(self, call: _Call) -> list[ExternalOutcome]:
        stream = self._concrete(call, call.arguments[0], "stream")
        return self._returns(call, sx.const(self._stream(call, stream)[1], 64))

    def _rewind(self, call: _Call) -> list[ExternalOutcome]:
        stream = self._concrete(call, call.arguments[0], "stream")
        self._seek(call, stream, 0, 0)
        return self._returns_zero(call)

    def _fgetc(self, call: _Call) -> list[ExternalOutcome]:
        stream = self._concrete(call, call.arguments[0], "stream")
        content, position = self._stream(call, stream)
        if position >= len(content):
            return self._returns(call, sx.const(0xFFFF_FFFF, 64))  # EOF
        self._advance(call, stream, 1)
        return self._returns(call, sx.zero_extend(content[position], 64))

    def _fputc(self, call: _Call) -> list[ExternalOutcome]:
        stream = self._concrete(call, call.arguments[0 + 1], "stream")
        byte = sx.extract(call.arguments[0], 0, 8)
        self._written(call, stream, [byte])
        return self._returns(call, sx.zero_extend(byte, 64))

    def _written(self, call: _Call, stream: int, content: list[Expr]) -> None:
        """Bytes the program writes: to the output it prints, or into the file it opened."""
        io = call.state.io
        if stream in (STANDARD_STREAMS["stdout"], STANDARD_STREAMS["stderr"]):
            io.stdout.extend(content)
            return
        item = io.files.get(stream)
        if item is None:
            raise _Unsupported(f"writing to stream {stream:#x}, which was not opened here")
        position = io.positions.get(stream, 0)
        kept = list(item.content[:position]) + content
        io.files[stream] = OpenFile(item.name, tuple(kept))
        io.contents[item.name] = tuple(kept)
        io.positions[stream] = len(kept)

    def _fwrite(self, call: _Call) -> list[ExternalOutcome]:
        buffer = self._concrete(call, call.arguments[0], "buffer")
        size = self._concrete(call, call.arguments[1], "size")
        count = self._concrete(call, call.arguments[2], "count")
        stream = self._concrete(call, call.arguments[3], "stream")
        self._written(call, stream, [self._byte(call, buffer + n) for n in range(size * count)])
        return self._returns(call, sx.const(count, 64))

    def _concatenate(self, call: _Call, limit: int | None) -> list[ExternalOutcome]:
        """`strcat` and `strncat`: the source written where the destination ends.

        Either string may end at a byte the input decides, so each write keeps what was
        there unless this position is really part of the result.
        """
        destination = self._concrete(call, call.arguments[0], "destination")
        source = self._concrete(call, call.arguments[1], "source")
        existing = self._string_bytes(call, destination)
        appended = self._string_bytes(call, source)
        if limit is not None:
            appended = appended[:limit]
        terminated = limit is not None and len(appended) == limit
        for start, _ in enumerate([*existing, _ZERO_BYTE]):
            # The destination ends at `start` when every byte before it is non-zero.
            ends_here = sx.bool_and(
                *(sx.bool_not(sx.equal(byte, _ZERO_BYTE)) for byte in existing[:start]),
                *([sx.equal(existing[start], _ZERO_BYTE)] if start < len(existing) else []),
            )
            if ends_here is sx.FALSE:
                continue
            copying = ends_here
            tail: list[Expr] = [] if terminated else [_ZERO_BYTE]
            for offset, byte in enumerate([*appended, *tail]):
                old = self._byte(call, destination + start + offset)
                self._write(call, destination + start + offset, sx.ite(copying, byte, old))
                copying = sx.bool_and(copying, sx.bool_not(sx.equal(byte, _ZERO_BYTE)))
            if terminated:
                # `strncat` terminates after the bytes it copied, which is `limit` of them
                # only when none of them was itself the terminator: `copying` says so.
                end = destination + start + len(appended)
                self._write(call, end, sx.ite(copying, _ZERO_BYTE, self._byte(call, end)))
        return self._returns(call, sx.const(destination, 64))

    def _strstr(self, call: _Call) -> list[ExternalOutcome]:
        """`strstr`: the address where the needle starts, or NULL — one of a few places."""
        haystack = self._concrete(call, call.arguments[0], "string")
        needle_at = self._concrete(call, call.arguments[1], "needle")
        text = self._string_bytes(call, haystack)
        needle = self._string_bytes(call, needle_at)
        if not needle:
            return self._returns(call, sx.const(haystack, 64))
        result = sx.const(0, 64)
        for start in reversed(range(len(text) - len(needle) + 1)):
            matches = sx.bool_and(
                *(sx.equal(text[start + offset], byte) for offset, byte in enumerate(needle))
            )
            result = sx.ite(matches, sx.const(haystack + start, 64), result)
        return self._returns(call, result)

    def _fread(self, call: _Call) -> list[ExternalOutcome]:
        buffer = self._concrete(call, call.arguments[0], "buffer")
        size = self._concrete(call, call.arguments[1], "size")
        count = self._concrete(call, call.arguments[2], "count")
        stream = self._concrete(call, call.arguments[3], "stream")
        content, position = self._stream(call, stream)
        taken = content[position : position + size * count]
        for index, byte in enumerate(taken):
            self._write(call, buffer + index, byte)
        self._advance(call, stream, len(taken))
        return self._returns(call, sx.const(len(taken) // size if size else 0, 64))

    def _fgets(self, call: _Call) -> list[ExternalOutcome]:
        buffer = self._concrete(call, call.arguments[0], "buffer")
        size = self._concrete(call, sx.extract(call.arguments[1], 0, 32), "size")
        stream = self._concrete(call, call.arguments[2], "stream")
        content, position = self._stream(call, stream)
        io = call.state.io
        remaining = content[position:]
        if size <= 0 or size > 0x7FFFFFFF or not remaining:
            return self._returns(call, sx.const(0, 64))
        taken = remaining[: size - 1]
        count = sx.const(len(taken), 64)
        for index in reversed(range(len(taken))):
            count = sx.ite(sx.equal(taken[index], _NEWLINE), sx.const(index + 1, 64), count)
        for index, byte in enumerate(taken):
            offset = sx.const(index, 64)
            old = self._byte(call, buffer + index)
            terminator = sx.ite(sx.equal(offset, count), _ZERO_BYTE, old)
            self._write(
                call, buffer + index, sx.ite(sx.unsigned_less(offset, count), byte, terminator)
            )
        end = buffer + len(taken)
        old = self._byte(call, end)
        self._write(call, end, sx.ite(sx.equal(count, sx.const(len(taken), 64)), _ZERO_BYTE, old))
        if stream == STANDARD_STREAMS["stdin"]:
            io.stdin_reads.append((position, position + len(taken), True))
        consumed = call.executor.unique_value(call.state, count)
        if consumed is None:
            # What follows is only meaningful once the line's length is known.
            note = "input after a symbolic-length fgets line is treated as empty"
            self._truncate(call, stream, position, note)
        else:
            self._advance(call, stream, consumed)
        return self._returns(call, sx.const(buffer, 64))

    def _truncate(self, call: _Call, stream: int, position: int, note: str) -> None:
        """Forget what a stream holds past `position`, where the model cannot follow it.

        `note` is what to say if the program reads this stream again; until it does, the
        bytes nobody looks at cost nothing, so nothing is reported.
        """
        io = call.state.io
        io.unknown_from[stream] = note
        if stream == STANDARD_STREAMS["stdin"]:
            io.stdin = io.stdin[:position]
            return
        item = io.files[stream]
        io.files[stream] = OpenFile(item.name, item.content[:position])

    @staticmethod
    def _at_end(call: _Call, stream: int = STANDARD_STREAMS["stdin"]) -> None:
        """A read found nothing left: say so when the model is the reason there is nothing."""
        note = call.state.io.unknown_from.get(stream)
        if note is not None:
            call.executor.approximate(call.state, note, may_hide_paths=True)

    def _time(self, call: _Call) -> list[ExternalOutcome]:
        """`time(t)`: the second this run happens in, which the solver chooses.

        A program that reads the clock is solved for a time it could have been run at,
        and the answer says which one — rather than a constant assumed here.
        """
        state = call.state
        if state.io.clock is None:
            clock = sx.symbol(CLOCK_SYMBOL, 64)
            call.executor.add_constraint(
                state,
                sx.unsigned_less_equal(clock, sx.const(_LATEST_CLOCK, 64)),
                ConstraintKind.ENVIRONMENT,
                call.origin,
                "the clock reads a second in this century",
            )
            state.io.clock = clock
        destination = call.executor.unique_value(state, call.arguments[0])
        if destination:
            for index in range(8):
                self._write(call, destination + index, sx.extract(state.io.clock, index * 8, 8))
        return self._returns(call, state.io.clock)

    def _srand(self, call: _Call) -> list[ExternalOutcome]:
        """`srand(seed)`: the generator is modeled exactly, so the seed has to be a number.

        A seed the input or the clock decides is settled here by picking one it could be
        and saying so: the rest of the run then follows that choice, and a search that
        finds nothing is reported as incomplete rather than as no answer existing.
        """
        wanted = sx.extract(call.arguments[0], 0, 32)
        seed = call.executor.unique_value(call.state, wanted)
        if seed is None:
            seed = self._choose(call, wanted, "srand seed")
        call.state.io.random = glibc_random.seeded(seed)
        return self._returns_zero(call)

    def _choose(self, call: _Call, value: Expr, what: str) -> int:
        """Settle `value` on one of the values it could take, and record the choice."""
        model = call.executor.solve_with(call.state, sx.symbols(value), [])
        chosen = None if model is None else evaluate(value, model)
        if chosen is None:
            raise _Unsupported(f"{what} is symbolic ({sx.render(value, 80)})")
        call.executor.add_constraint(
            call.state,
            sx.equal(value, sx.const(chosen, value.width)),
            ConstraintKind.ENVIRONMENT,
            call.origin,
            f"{what} is {chosen}",
        )
        call.executor.approximate(
            call.state, f"{what} was settled on {chosen}", may_hide_paths=True
        )
        return chosen

    def _rand(self, call: _Call) -> list[ExternalOutcome]:
        call.state.io.random, value = glibc_random.advance(call.state.io.random)
        return self._returns(call, sx.const(value, 64))

    def _gets(self, call: _Call) -> list[ExternalOutcome]:
        """A line without its newline, however long: bytes the program cannot hold crash it."""
        buffer = self._concrete(call, call.arguments[0], "buffer")
        io = call.state.io
        remaining = io.stdin[io.stdin_position :]
        if not remaining:
            self._at_end(call)
            return self._returns(call, sx.const(0, 64))
        length = sx.const(len(remaining), 64)
        for index in reversed(range(len(remaining))):
            length = sx.ite(sx.equal(remaining[index], _NEWLINE), sx.const(index, 64), length)
        for index in range(len(remaining) + 1):
            address = buffer + index
            position = sx.const(index, 64)
            if not call.state.memory.accessible(address, 1, write=True):
                # A longer line overruns into memory that faults in the real program too.
                call.executor.add_constraint(
                    call.state,
                    sx.unsigned_less(length, position),
                    ConstraintKind.LIBRARY,
                    call.origin,
                    "gets line fits in writable memory",
                )
                break
            byte = remaining[index] if index < len(remaining) else _ZERO_BYTE
            old = call.state.memory.read_byte(address)
            terminator = sx.ite(sx.equal(position, length), _ZERO_BYTE, old)
            call.state.memory.write_byte(
                address, sx.ite(sx.unsigned_less(position, length), byte, terminator)
            )
        io.stdin_reads.append((io.stdin_position, io.stdin_position + len(remaining), True))
        consumed = call.executor.unique_value(call.state, length)
        if consumed is None:
            note = "stdin after a symbolic-length gets line is treated as empty"
            self._truncate(call, STANDARD_STREAMS["stdin"], io.stdin_position, note)
        else:
            io.stdin_position += consumed + (consumed < len(remaining))
        return self._returns(call, sx.const(buffer, 64))

    def _getchar(self, call: _Call) -> list[ExternalOutcome]:
        io = call.state.io
        if io.stdin_position >= len(io.stdin):
            self._at_end(call)
            return self._returns(call, sx.const(0xFFFFFFFF, 64))
        byte = io.stdin[io.stdin_position]
        io.stdin_reads.append((io.stdin_position, io.stdin_position + 1, False))
        io.stdin_position += 1
        return self._returns(call, sx.zero_extend(byte, 64))

    # -- output ----------------------------------------------------------------------------

    def _puts(self, call: _Call) -> list[ExternalOutcome]:
        text = self._string_bytes(call, self._concrete(call, call.arguments[0], "string"))
        call.state.io.stdout.extend([*text, _NEWLINE])
        return self._returns(call, sx.const(len(text) + 1, 64))

    def _putchar(self, call: _Call) -> list[ExternalOutcome]:
        byte = sx.extract(call.arguments[0], 0, 8)
        call.state.io.stdout.append(byte)
        return self._returns(call, sx.zero_extend(byte, 64))

    def _fputs(self, call: _Call) -> list[ExternalOutcome]:
        text = self._string_bytes(call, self._concrete(call, call.arguments[0], "string"))
        stream = self._concrete(call, call.arguments[1], "stream")
        if stream == STANDARD_STREAMS["stdout"]:
            call.state.io.stdout.extend(text)
        elif stream != STANDARD_STREAMS["stderr"]:
            raise _Unsupported(f"fputs to stream {stream:#x}")
        return self._returns(call, sx.const(1, 64))

    def _sprintf(self, call: _Call) -> list[ExternalOutcome]:
        return self._format_into(call, buffer_index=0, format_index=1, first=2, limit=None)

    def _snprintf(self, call: _Call) -> list[ExternalOutcome]:
        limit = self._concrete(call, call.arguments[1], "size")
        return self._format_into(call, buffer_index=0, format_index=2, first=3, limit=limit)

    def _format_into(
        self, call: _Call, buffer_index: int, format_index: int, first: int, limit: int | None
    ) -> list[ExternalOutcome]:
        """`sprintf` written out exactly, for the conversions whose length is not data's.

        A `%d` of a symbolic number could be one byte or twenty, and everything after it
        would move; those are refused rather than approximated. `%02x` of a symbolic byte
        is always two bytes, so hex encoding — what challenges usually do — works.
        """
        buffer = self._concrete(call, call.arguments[buffer_index], "buffer")
        template = self._string_bytes(
            call, self._concrete(call, call.arguments[format_index], "format")
        )
        if any(not byte.is_const for byte in template):
            raise _Unsupported("the format string is symbolic")
        try:
            pieces = formatting.parse_format(bytes(byte.value for byte in template))
        except formatting.FormatError as error:
            raise _Unsupported(str(error)) from error
        content: list[Expr] = []
        index = first
        for piece in pieces:
            if isinstance(piece, bytes):
                content.extend(sx.const(byte, 8) for byte in piece)
                continue
            value = self._variadic(call, index)
            index += 1
            content.extend(self._converted(call, piece, value))
        if limit is not None:
            content = content[: max(0, limit - 1)]
        for offset, byte in enumerate(content):
            self._write(call, buffer + offset, byte)
        self._write(call, buffer + len(content), _ZERO_BYTE)
        return self._returns(call, sx.const(len(content), 64))

    def _fits(self, call: _Call, value: Expr, digits: int) -> bool:
        """Whether this path allows only values that `digits` hex characters can hold."""
        limit = sx.const(1 << (4 * digits), value.width)
        too_large = sx.bool_not(sx.unsigned_less(value, limit))
        return call.executor.feasible(call.state, [too_large]) is Status.UNSAT

    def _hex_conversion(
        self, call: _Call, directive: formatting.Directive, value: Expr
    ) -> list[Expr]:
        """`%02x` and friends: as many characters as the field is wide, whatever the value.

        A hex conversion writes at least as many characters as the field is wide, and more
        only when the value needs more digits than fit. A byte printed with `%2X` never
        does, and the path condition is what says so, so the solver is asked.
        """
        width = int(directive.width or b"0")
        digits = (directive.bits + 3) // 4
        if b"-" in directive.flags or not width:
            raise _Unsupported(
                f"%{directive.flags.decode()}{directive.width.decode()}"
                f"{directive.conversion.decode()} of a value whose length in characters "
                "the input decides"
            )
        if width < digits:
            # A wider value would write more characters and move everything after it. The
            # program's own comparison almost always rules that out; assume it, and say so.
            digits = width
            limit = sx.const(1 << (4 * width), value.width)
            if not self._fits(call, value, width):
                call.executor.add_constraint(
                    call.state,
                    sx.unsigned_less(value, limit),
                    ConstraintKind.LIBRARY,
                    call.origin,
                    "a hex conversion writes no more characters than its field is wide",
                )
                call.executor.approximate(
                    call.state,
                    f"values printed with %{directive.width.decode()}"
                    f"{directive.conversion.decode()} are assumed to fit that field",
                    may_hide_paths=True,
                )
        upper = directive.conversion == b"X"
        padding = sx.const(ord("0") if b"0" in directive.flags else ord(" "), 8)
        narrowed = sx.extract(value, 0, directive.bits) if value.width > directive.bits else value
        characters = [padding] * (width - digits)
        above: Expr = sx.TRUE  # every digit before this one is zero
        for position in range(digits):
            nibble = sx.extract(narrowed, 4 * (digits - 1 - position), 4)
            digit = _hex_digit(nibble, upper)
            last = position == digits - 1
            characters.append(digit if last else sx.ite(above, padding, digit))
            if not last:
                above = sx.bool_and(above, sx.equal(nibble, sx.const(0, 4)))
                characters[-1] = sx.ite(above, padding, digit)
        return characters

    def _converted(self, call: _Call, directive: formatting.Directive, value: Expr) -> list[Expr]:
        """The bytes one conversion writes, when their number does not depend on the value."""
        conversion = directive.conversion
        if conversion == b"s":
            return self._string_bytes(call, self._concrete(call, value, "string"))
        known = call.executor.unique_value(call.state, value)
        if known is not None:
            return [sx.const(byte, 8) for byte in formatting.format_one(directive, known)]
        if conversion == b"c":
            return [sx.extract(value, 0, 8)]
        if conversion in (b"x", b"X"):
            return self._hex_conversion(call, directive, value)
        raise _Unsupported(
            f"%{conversion.decode()} of a value whose length in characters the input decides"
        )

    def _printf(self, call: _Call) -> list[ExternalOutcome]:
        format_index = 1 if call.name == "__printf_chk" else 0
        template = self._string_bytes(
            call, self._concrete(call, call.arguments[format_index], "format")
        )
        if any(not byte.is_const for byte in template):
            raise _Unsupported("the format string is symbolic")
        literal = bytes(byte.value for byte in template)
        if b"%" not in literal.replace(b"%%", b""):
            text = literal.replace(b"%%", b"%")
            call.state.io.stdout.extend(sx.const(byte, 8) for byte in text)
            return self._returns(call, sx.const(len(text), 64))
        # Formatted output is not needed to decide reachability, but its length could be:
        # model it as unconstrained and record the over-approximation. Solutions are
        # re-checked by concrete execution, which formats exactly.
        call.executor.approximate(
            call.state,
            f"printf result at {call.origin.address:#x} is unconstrained",
            may_hide_paths=False,
        )
        return self._returns(
            call, sx.symbol(f"__printf_{call.origin.address:x}_{call.state.id}", 64)
        )

    # -- numbers ---------------------------------------------------------------------------

    def _parse(self, call: _Call) -> list[tuple[State, Expr, Expr]]:
        """strtol(text, &end, 10), split by the shape of the number.

        Plain numbers (no leading whitespace, an optional sign, at most ten digits) each get
        a state with a simple value; one more state covers every other input with the exact
        scanner, so no input is left out. Longer numbers are rare and much harder for the
        solver, so that state is explored last.
        """
        address = self._concrete(call, call.arguments[0], "string")
        text = self._string_bytes(call, address)
        options: list[tuple[Expr, tuple[int, int] | None]] = []
        if text:
            first = text[0]
            sign = sx.bool_or(
                sx.equal(first, sx.const(0x2B, 8)), sx.equal(first, sx.const(0x2D, 8))
            )
            options.append(
                (sx.bool_not(sx.bool_or(sign, _is_digit(first), _is_space(first))), (0, 0))
            )
            for signed in (0, 1):
                head = sign if signed else _is_digit(first)
                digits = sx.TRUE
                for count in range(1, min(_PLAIN_DIGITS, len(text) - signed) + 1):
                    digits = sx.bool_and(digits, _is_digit(text[signed + count - 1]))
                    after = signed + count
                    ends = sx.TRUE if after == len(text) else sx.bool_not(_is_digit(text[after]))
                    options.append((sx.bool_and(head, digits, ends), (signed, count)))
        plain = sx.bool_or(*(condition for condition, _ in options))
        options.append((sx.bool_not(plain), None))
        results: list[tuple[State, Expr, Expr]] = []
        for state, shape in _split(call, call.state, options, "number shape"):
            if shape is None:
                # Unusual numbers (leading whitespace, long digit runs) come after plain ones.
                state.decisions += _PLAIN_DIGITS
                result, end, any_digit = _strtol_expression(text)
                results.append((state, result, sx.ite(any_digit, end, sx.const(0, 64))))
                continue
            signed, count = shape
            magnitude = sx.const(0, 64)
            for byte in text[signed : signed + count]:
                numeral = sx.zero_extend(sx.sub(byte, sx.const(0x30, 8)), 64)
                magnitude = sx.add(sx.mul(magnitude, sx.const(10, 64)), numeral)
            negative = sx.equal(text[0], sx.const(0x2D, 8)) if signed else sx.FALSE
            value = sx.ite(negative, sx.negate(magnitude), magnitude)
            results.append((state, value, sx.const(signed + count if count else 0, 64)))
        return results

    def _atoi(self, call: _Call) -> list[ExternalOutcome]:
        return [
            Returned(state, self._outputs(call, sx.zero_extend(sx.extract(result, 0, 32), 64)))
            for state, result, _ in self._parse(call)
        ]

    def _atol(self, call: _Call) -> list[ExternalOutcome]:
        return [
            Returned(state, self._outputs(call, result)) for state, result, _ in self._parse(call)
        ]

    def _strtol(self, call: _Call) -> list[ExternalOutcome]:
        base = self._concrete(call, sx.extract(call.arguments[2], 0, 32), "base")
        if base != 10:
            raise _Unsupported(f"base {base}")
        end_pointer = self._concrete(call, call.arguments[1], "end pointer")
        address = self._concrete(call, call.arguments[0], "string")
        outcomes: list[ExternalOutcome] = []
        for state, result, end in self._parse(call):
            if end_pointer:
                stored = sx.add(sx.const(address, 64), end)
                for index in range(8):
                    location = end_pointer + index
                    if not state.memory.accessible(location, 1, write=True):
                        raise _Fault(f"write to unwritable memory at {location:#x}")
                    state.memory.write_byte(location, sx.extract(stored, index * 8, 8))
            outcomes.append(Returned(state, self._outputs(call, result)))
        return outcomes

    # -- characters ------------------------------------------------------------------------

    def _case(self, call: _Call, first: int, last: int, delta: int) -> list[ExternalOutcome]:
        character = sx.extract(call.arguments[0], 0, 32)
        mapped = sx.ite(
            _in_signed_range(character, first, last),
            sx.add(character, sx.const(delta & 0xFFFFFFFF, 32)),
            sx.ite(
                _in_signed_range(character, ctype.FIRST, -2),
                sx.add(character, sx.const(0x100, 32)),
                character,
            ),
        )
        return self._returns(call, sx.zero_extend(mapped, 64))

    def _classify(self, call: _Call, flag: int) -> list[ExternalOutcome]:
        character = sx.extract(call.arguments[0], 0, 32)
        in_table = _in_signed_range(character, ctype.FIRST, ctype.LAST)
        if in_table is not sx.TRUE:
            executor, state = call.executor, call.state
            if executor.feasible(state, [sx.bool_not(in_table)]) is not Status.UNSAT:
                if executor.feasible(state, [in_table]) is Status.UNSAT:
                    raise _Unsupported("the character is outside the classification table")
                executor.add_constraint(
                    state,
                    in_table,
                    ConstraintKind.LIBRARY,
                    call.origin,
                    f"{call.name} is undefined outside -128..255",
                )
                executor.approximate(
                    state,
                    f"{call.name} at {call.origin.address:#x} assumes its argument indexes "
                    "the table",
                    may_hide_paths=True,
                )
        runs: list[tuple[int, int]] = []
        for code in range(0x80):
            if ctype.classification(code) & flag:
                if runs and runs[-1][1] == code - 1:
                    runs[-1] = (runs[-1][0], code)
                else:
                    runs.append((code, code))
        member = sx.bool_or(*(_in_signed_range(character, low, high) for low, high in runs))
        return self._returns(call, sx.ite(member, sx.const(flag, 64), sx.const(0, 64)))

    # -- scanf -----------------------------------------------------------------------------

    def _fscanf(self, call: _Call) -> list[ExternalOutcome]:
        """`fscanf(stream, ...)`: scanf reading whatever that stream holds."""
        stream = self._concrete(call, call.arguments[0], "stream")
        self._stream(call, stream)  # refuses a stream this program never opened
        return self._scan(call, format_index=1, stream=stream)

    def _scanf(self, call: _Call) -> list[ExternalOutcome]:
        """scanf over the symbolic stdin stream, forking where the input's shape decides.

        Every alternative (how a token ends, whether a conversion fails) becomes its own
        state with the condition that selects it, so positions in the stream stay concrete.
        Whitespace skipped by a directive is never visible to the program: an input that
        skips several whitespace bytes behaves exactly like one that skips a single byte
        of it, so only zero or one skipped byte is explored.
        """
        return self._scan(call, format_index=0, stream=0)

    def _sscanf(self, call: _Call) -> list[ExternalOutcome]:
        """`sscanf(text, ...)`: scanf over a string in memory rather than a stream."""
        address = self._concrete(call, call.arguments[0], "text")
        data = tuple(self._string_bytes(call, address))
        return self._scan(call, format_index=1, stream=0, data=data)

    def _scan(
        self, call: _Call, format_index: int, stream: int, data: tuple[Expr, ...] | None = None
    ) -> list[ExternalOutcome]:
        template = self._string_bytes(
            call, self._concrete(call, call.arguments[format_index], "format")
        )
        if any(not byte.is_const for byte in template):
            raise _Unsupported("the format string is symbolic")
        try:
            directives = scanning.parse_format(bytes(byte.value for byte in template))
        except scanning.FormatError as error:
            raise _Unsupported(str(error)) from error
        assignments = sum(
            1 for directive in directives if directive.assigns and _converts(directive)
        )
        destinations = [
            self._concrete(call, self._variadic(call, format_index + 1 + index), "pointer")
            for index in range(assignments)
        ]
        return _Scanner(self, call, directives, destinations, stream, data).run()

    def _variadic(self, call: _Call, index: int) -> Expr:
        registers = self.convention.integer_parameters
        if index < len(registers):
            return call.arguments[index]
        stack = call.registers.get(self.convention.stack_pointer)
        if stack is None:
            raise _Unsupported("stack-passed arguments without a stack pointer")
        address = self._concrete(call, stack, "stack pointer") + 8 * (1 + index - len(registers))
        try:
            return call.state.memory.load(address, 64)
        except MemoryFaultError as fault:
            raise _Fault(str(fault)) from fault

    # -- process ---------------------------------------------------------------------------

    def _exit(self, call: _Call) -> list[ExternalOutcome]:
        return [Exited(call.state, sx.extract(call.arguments[0], 0, 8))]

    def _abort(self, call: _Call) -> list[ExternalOutcome]:
        return [Failed(call.state, StopReason.FAULT, f"{call.name} terminates the program")]

    def _allocate(self, call: _Call, size: int) -> int:
        io = call.state.io
        if io.heap_next == 0:
            io.heap_next = HEAP_START
        address = io.heap_next
        if address + max(1, size) > HEAP_START + HEAP_SIZE:
            return 0
        io.heap_next = (address + max(1, size) + 31) & ~15
        return address

    def _ptrace(self, call: _Call) -> list[ExternalOutcome]:
        """`PTRACE_TRACEME` succeeds: nothing is tracing the program.

        That is the same situation `--verify` runs the binary in, and the branch an
        anti-debugging check takes when it is not under a debugger. Other requests are a
        debugger's own, and are left unmodeled.
        """
        request = self._concrete(call, call.arguments[0], "ptrace request")
        if request != _PTRACE_TRACEME:
            raise _Unsupported(f"ptrace request {request}")
        state = call.state
        if state.io.traced is None:
            traced = sx.symbol(TRACED_SYMBOL, 64)
            call.executor.add_constraint(
                state,
                sx.bool_or(sx.equal(traced, sx.const(0, 64)), sx.equal(traced, _TRACED)),
                ConstraintKind.ENVIRONMENT,
                call.origin,
                "ptrace(PTRACE_TRACEME) fails only under a debugger",
            )
            state.io.traced = traced
        return self._returns(call, state.io.traced)

    def _malloc(self, call: _Call) -> list[ExternalOutcome]:
        size = self._concrete(call, call.arguments[0], "size")
        return self._returns(call, sx.const(self._allocate(call, size), 64))

    def _guard_acquire(self, call: _Call) -> list[ExternalOutcome]:
        """`__cxa_guard_acquire`: whether this function-local static still needs building."""
        guard = self._concrete(call, call.arguments[0], "guard")
        done = sx.equal(self._byte(call, guard), _ZERO_BYTE)
        return self._returns(call, sx.flag(done, 64))

    def _guard_release(self, call: _Call) -> list[ExternalOutcome]:
        """`__cxa_guard_release`: the static is built, so the next call skips it."""
        guard = self._concrete(call, call.arguments[0], "guard")
        self._write(call, guard, sx.const(1, 8))
        return self._returns(call, sx.const(0, 64))

    def _calloc(self, call: _Call) -> list[ExternalOutcome]:
        count = self._concrete(call, call.arguments[0], "count")
        size = self._concrete(call, call.arguments[1], "size")
        address = self._allocate(call, count * size)
        for index in range(count * size if address else 0):
            self._write(call, address + index, _ZERO_BYTE)
        return self._returns(call, sx.const(address, 64))


def _strtol_expression(text: list[Expr]) -> tuple[Expr, Expr, Expr]:
    """strtol(text, &end, 10) over possibly symbolic bytes, exactly.

    Returns the saturated 64-bit value, the index just past the last digit, and whether
    any digit was read. The C scanner is run over every byte as a small state machine
    whose state is carried in if-then-else expressions.
    """
    skipping, signed, in_digits, finished = sx.TRUE, sx.FALSE, sx.FALSE, sx.FALSE
    negative, overflow, any_digit = sx.FALSE, sx.FALSE, sx.FALSE
    value = sx.const(0, 64)
    end = sx.const(0, 64)
    cutoff = sx.const((1 << 64) // 10, 64)
    for index, byte in enumerate(text):
        digit = _in_range(byte, 0x30, 0x39)
        space = sx.bool_or(*(sx.equal(byte, sx.const(code, 8)) for code in ctype.WHITESPACE))
        sign = sx.bool_or(sx.equal(byte, sx.const(0x2B, 8)), sx.equal(byte, sx.const(0x2D, 8)))
        stay = sx.bool_and(skipping, space)
        take_sign = sx.bool_and(skipping, sign)
        take_first = sx.bool_and(sx.bool_or(skipping, signed), digit)
        take_more = sx.bool_and(in_digits, digit)
        numeral = sx.zero_extend(sx.sub(byte, sx.const(0x30, 8)), 64)
        too_big = sx.bool_or(
            sx.unsigned_less(cutoff, value),
            sx.bool_and(
                sx.equal(value, cutoff),
                sx.unsigned_less(sx.const(((1 << 64) - 1) % 10, 64), numeral),
            ),
        )
        overflow = sx.bool_or(overflow, sx.bool_and(take_more, too_big))
        value = sx.ite(
            take_first,
            numeral,
            sx.ite(
                sx.bool_and(take_more, sx.bool_not(too_big)),
                sx.add(sx.mul(value, sx.const(10, 64)), numeral),
                value,
            ),
        )
        minus = sx.equal(byte, sx.const(0x2D, 8))
        negative = sx.bool_or(
            sx.bool_and(take_sign, minus), sx.bool_and(sx.bool_not(take_sign), negative)
        )
        took_digit = sx.bool_or(take_first, take_more)
        end = sx.ite(took_digit, sx.const(index + 1, 64), end)
        any_digit = sx.bool_or(any_digit, take_first)
        finished = sx.bool_or(finished, sx.bool_not(sx.bool_or(stay, take_sign, took_digit)))
        skipping, signed, in_digits = stay, take_sign, took_digit
    del finished  # every later step already requires a phase that finishing leaves
    limit = sx.const(1 << 63, 64)
    too_large = sx.bool_or(
        overflow,
        sx.bool_and(negative, sx.unsigned_less(limit, value)),
        sx.bool_and(sx.bool_not(negative), sx.unsigned_less_equal(limit, value)),
    )
    saturated = sx.ite(negative, limit, sx.const((1 << 63) - 1, 64))
    result = sx.ite(too_large, saturated, sx.ite(negative, sx.negate(value), value))
    return result, end, any_digit


_PLAIN_DIGITS = 10
"""Digits of a plain number: enough for any 32-bit value, never enough to overflow long."""
_SAFE_DIGITS = 18
"""Digits that can never overflow a 64-bit long."""


def _token_values(digits: list[Expr], negative: Expr) -> list[Expr]:
    """strtol's saturated value of a sign and the first k `digits`, for every k from 1.

    Exactly what `_strtol_expression` computes for such a token, built once for all
    lengths: each value extends the previous one.
    """
    cutoff = sx.const((1 << 64) // 10, 64)
    last_digit = sx.const(((1 << 64) - 1) % 10, 64)
    limit = sx.const(1 << 63, 64)
    saturated = sx.ite(negative, limit, sx.const((1 << 63) - 1, 64))
    value = sx.const(0, 64)
    overflow = sx.FALSE
    values: list[Expr] = []
    for index, byte in enumerate(digits):
        numeral = sx.zero_extend(sx.sub(byte, sx.const(0x30, 8)), 64)
        if index < _SAFE_DIGITS:
            value = sx.add(sx.mul(value, sx.const(10, 64)), numeral)
            values.append(sx.ite(negative, sx.negate(value), value))
            continue
        too_big = sx.bool_or(
            sx.unsigned_less(cutoff, value),
            sx.bool_and(sx.equal(value, cutoff), sx.unsigned_less(last_digit, numeral)),
        )
        overflow = sx.bool_or(overflow, too_big)
        value = sx.ite(too_big, value, sx.add(sx.mul(value, sx.const(10, 64)), numeral))
        too_large = sx.bool_or(
            overflow,
            sx.bool_and(negative, sx.unsigned_less(limit, value)),
            sx.bool_and(sx.bool_not(negative), sx.unsigned_less_equal(limit, value)),
        )
        values.append(sx.ite(too_large, saturated, sx.ite(negative, sx.negate(value), value)))
    return values


def _split[T](
    call: _Call, state: State, options: list[tuple[Expr, T]], note: str
) -> list[tuple[State, T]]:
    """One state per feasible option; the options' conditions must exclude each other.

    Options come in the order they should be explored (plain before unusual, short before
    long): the last one continues in `state`, renumbered so that it does not go first.
    """
    executor = call.executor
    chosen: list[tuple[State, T]] = []
    live = [(condition, tag) for condition, tag in options if condition is not sx.FALSE]
    known = _ByteTests.of(state)
    for index, (condition, tag) in enumerate(live):
        child = state if index == len(live) - 1 else state.fork(executor.new_state_id())
        if child is state and index:
            executor.renumber(child)
        executor.add_constraint(child, condition, ConstraintKind.LIBRARY, call.origin, note)
        if condition is sx.TRUE or known.satisfiable(condition):
            chosen.append((child, tag))
            continue
        if executor.feasible(child) is Status.UNSAT:
            continue
        chosen.append((child, tag))
    if len(chosen) > 1:
        # Options come in the order they should be explored, so later ones count as deeper
        # decisions: a plain four-digit number is tried long before a 200-digit one.
        for position, (child, _) in enumerate(chosen):
            child.decisions += 1 + position
    return chosen


_SATISFYING: dict[Expr, frozenset[int]] = {}


def _satisfying_values(test: Expr, name: str) -> frozenset[int]:
    """The byte values a single-byte test allows; the same tests recur constantly."""
    known = _SATISFYING.get(test)
    if known is None:
        known = frozenset(value for value in range(256) if evaluate(test, {name: value}))
        _SATISFYING[test] = known
    return known


def _conjuncts(condition: Expr) -> tuple[Expr, ...]:
    return condition.args if condition.op is sx.Op.BOOL_AND else (condition,)


def _single_byte(condition: Expr) -> str | None:
    """The one input byte `condition` tests, if that is all it does."""
    found = sx.symbols(condition)
    return found[0].name if len(found) == 1 and found[0].width == 8 else None


@dataclass(frozen=True, slots=True)
class _ByteTests:
    """The path condition's tests on individual bytes, and the bytes it ties to others."""

    per_byte: dict[str, list[Expr]]
    entangled: frozenset[str]

    @classmethod
    def of(cls, state: State) -> _ByteTests:
        per_byte: dict[str, list[Expr]] = {}
        entangled: set[str] = set()
        for constraint in state.constraints:
            for part in _conjuncts(constraint.condition):
                name = _single_byte(part)
                if name is None:
                    entangled.update(symbol.name for symbol in sx.symbols(part))
                else:
                    per_byte.setdefault(name, []).append(part)
        return cls(per_byte, frozenset(entangled))

    def satisfiable(self, condition: Expr) -> bool:
        """Whether the path condition plus `condition` holds for some input, without a solver.

        The shapes a scan forks on test single input bytes. When nothing else ties those
        bytes to the rest of the path, each byte can be tried over all 256 values on its
        own: the rest of the path already has a model, and these bytes cannot spoil it.
        """
        tests: dict[str, list[Expr]] = {}
        for part in _conjuncts(condition):
            name = _single_byte(part)
            if name is None or name in self.entangled:
                return False
            tests.setdefault(name, []).append(part)
        for name, group in tests.items():
            allowed = set(range(256))
            for test in (*self.per_byte.get(name, []), *group):
                allowed &= _satisfying_values(test, name)
                if not allowed:
                    return False
        return True


def _in_range(byte: Expr, low: int, high: int) -> Expr:
    width = byte.width
    return sx.bool_and(
        sx.unsigned_less_equal(sx.const(low, width), byte),
        sx.unsigned_less_equal(byte, sx.const(high, width)),
    )


def _in_signed_range(value: Expr, low: int, high: int) -> Expr:
    width = value.width
    return sx.bool_and(
        sx.signed_less_equal(sx.const(low & ((1 << width) - 1), width), value),
        sx.signed_less_equal(value, sx.const(high & ((1 << width) - 1), width)),
    )


def _is_space(byte: Expr) -> Expr:
    return sx.bool_or(*(sx.equal(byte, sx.const(code, 8)) for code in ctype.WHITESPACE))


def _is_digit(byte: Expr) -> Expr:
    return _in_range(byte, 0x30, 0x39)


def _is_radix_digit(byte: Expr, base: int) -> Expr:
    """Whether `byte` is a digit in the given radix (16 or 8; 10 as a fallback)."""
    if base == 16:
        return sx.bool_or(
            _in_range(byte, 0x30, 0x39), _in_range(byte, 0x41, 0x46), _in_range(byte, 0x61, 0x66)
        )
    if base == 8:
        return _in_range(byte, 0x30, 0x37)
    return _in_range(byte, 0x30, 0x39)


def _radix_digit_value(byte: Expr, base: int) -> Expr:
    """The 0..base-1 value of a digit byte, as a 64-bit expression."""
    decimal = sx.zero_extend(sx.sub(byte, sx.const(0x30, 8)), 64)
    if base != 16:
        return decimal
    return sx.ite(
        _in_range(byte, 0x30, 0x39),
        decimal,
        sx.ite(
            _in_range(byte, 0x41, 0x46),
            sx.zero_extend(sx.sub(byte, sx.const(0x37, 8)), 64),
            sx.zero_extend(sx.sub(byte, sx.const(0x57, 8)), 64),
        ),
    )


def _radix_value(digits: list[Expr], base: int) -> Expr:
    """The value of a run of `digits` in `base`, wrapping at 64 bits."""
    value = sx.const(0, 64)
    for byte in digits:
        value = sx.add(sx.mul(value, sx.const(base, 64)), _radix_digit_value(byte, base))
    return value


def _scanset_ranges(charset: frozenset[int]) -> list[tuple[int, int]]:
    """The scanset's bytes as contiguous ranges, so the predicate stays compact."""
    ranges: list[tuple[int, int]] = []
    for value in sorted(charset):
        if ranges and value == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], value)
        else:
            ranges.append((value, value))
    return ranges


def _in_scanset(byte: Expr, directive: scanning.Directive) -> Expr:
    """Whether `byte` is matched by a `%[` scanset, honouring its negation."""
    ranges = _scanset_ranges(directive.charset)
    inside = (
        sx.bool_or(*(_in_range(byte, low, high) for low, high in ranges)) if ranges else sx.FALSE
    )
    return sx.bool_not(inside) if directive.negated else inside


def _converts(directive: scanning.Directive) -> bool:
    return directive.kind not in (scanning.DirectiveKind.SPACE, scanning.DirectiveKind.LITERAL)


@dataclass(slots=True)
class _Scan:
    """One way the input can drive scanf so far."""

    state: State
    position: int
    assigned: int = 0
    directive: int = 0
    result: int | None = None


class _Scanner:
    def __init__(
        self,
        libc: SymbolicLibc,
        call: _Call,
        directives: list[scanning.Directive],
        destinations: list[int],
        stream: int = 0,
        data: tuple[Expr, ...] | None = None,
    ) -> None:
        self.libc = libc
        self.call = call
        self.directives = directives
        self.destinations = destinations
        self.stream = stream or STANDARD_STREAMS["stdin"]
        self.data = data
        """Bytes to scan instead of a stream's, for `sscanf`: nothing is consumed."""
        self.result: Expr | None = None
        """What to return instead of the number of conversions, for `in >> n`."""

    def content(self, state: State) -> tuple[Expr, ...]:
        """What the stream being scanned holds."""
        if self.data is not None:
            return self.data
        if self.stream == STANDARD_STREAMS["stdin"]:
            return state.io.stdin
        item = state.io.files.get(self.stream)
        return item.content if item is not None else ()

    def position(self, state: State) -> int:
        if self.data is not None:
            return 0
        if self.stream == STANDARD_STREAMS["stdin"]:
            return state.io.stdin_position
        return state.io.positions.get(self.stream, 0)

    def run(self) -> list[ExternalOutcome]:
        pending = [_Scan(self.call.state, self.position(self.call.state))]
        outcomes: list[ExternalOutcome] = []
        while pending:
            scan = pending.pop()
            if scan.result is None and scan.directive == len(self.directives):
                scan.result = scan.assigned
            if scan.result is not None:
                outcomes.append(self._finish(scan))
                continue
            directive = self.directives[scan.directive]
            scan.directive += 1
            pending.extend(reversed(self._step(scan, directive)))
        return outcomes

    def _finish(self, scan: _Scan) -> ExternalOutcome:
        io = scan.state.io
        read_from = self.position(scan.state)
        if self.data is None and scan.position > read_from:
            if self.stream == STANDARD_STREAMS["stdin"]:
                io.stdin_reads.append((read_from, scan.position, False))
                io.stdin_position = scan.position
            else:
                io.positions[self.stream] = scan.position
        outputs = dict(self.call.registers)
        result = (scan.result or 0) & 0xFFFFFFFF
        returns = self.result if self.result is not None else sx.const(result, 64)
        outputs[self.libc.convention.integer_returns[0]] = returns
        return Returned(scan.state, outputs)

    # -- stream ------------------------------------------------------------------------------

    def _byte(self, scan: _Scan, index: int) -> Expr | None:
        content = self.content(scan.state)
        return content[index] if index < len(content) else None

    def _fork[T](self, scan: _Scan, options: list[tuple[Expr, T]]) -> list[tuple[_Scan, T]]:
        """Split `scan` by mutually exclusive conditions, keeping the feasible ones."""
        return [
            (_Scan(state, scan.position, scan.assigned, scan.directive, scan.result), tag)
            for state, tag in _split(self.call, scan.state, options, "scanf input")
        ]

    def _skip_space(self, scan: _Scan) -> list[_Scan]:
        first = self._byte(scan, scan.position)
        if first is None:
            return [scan]
        second = self._byte(scan, scan.position + 1)
        second_ends = sx.TRUE if second is None else sx.bool_not(_is_space(second))
        branches = self._fork(
            scan,
            [
                (sx.bool_not(_is_space(first)), 0),
                (sx.bool_and(_is_space(first), second_ends), 1),
            ],
        )
        for branch, skipped in branches:
            branch.position += skipped
        return [branch for branch, _ in branches]

    # -- directives --------------------------------------------------------------------------

    def _step(self, scan: _Scan, directive: scanning.Directive) -> list[_Scan]:
        kind = directive.kind
        branches = [scan] if kind not in scanning.SKIPS_WHITESPACE else self._skip_space(scan)
        if kind is scanning.DirectiveKind.SPACE:
            return branches
        result: list[_Scan] = []
        for branch in branches:
            byte = self._byte(branch, branch.position)
            if byte is None:
                branch.result = scanning.EOF if not branch.assigned else branch.assigned
                result.append(branch)
            elif kind is scanning.DirectiveKind.LITERAL:
                result.extend(self._literal(branch, directive, byte))
            elif kind is scanning.DirectiveKind.STRING:
                result.extend(self._string(branch, directive))
            elif kind is scanning.DirectiveKind.SCANSET:
                result.extend(self._scanset(branch, directive))
            elif kind is scanning.DirectiveKind.CHARACTERS:
                result.append(self._characters(branch, directive))
            else:
                result.extend(self._decimal(branch, directive))
        return result

    def _literal(self, scan: _Scan, directive: scanning.Directive, byte: Expr) -> list[_Scan]:
        matches = sx.equal(byte, sx.const(directive.literal, 8))
        branches = self._fork(scan, [(matches, 1), (sx.bool_not(matches), 0)])
        for branch, matched in branches:
            if matched:
                branch.position += 1
            else:
                branch.result = branch.assigned
        return [branch for branch, _ in branches]

    def _store(self, scan: _Scan, directive: scanning.Directive, content: list[Expr]) -> None:
        if not directive.assigns:
            return
        destination = self.destinations[scan.assigned]
        for index, byte in enumerate(content):
            address = destination + index
            if not scan.state.memory.accessible(address, 1, write=True):
                raise _Fault(f"scanf writes to unwritable memory at {address:#x}")
            scan.state.memory.write_byte(address, byte)
        scan.assigned += 1

    def _string(self, scan: _Scan, directive: scanning.Directive) -> list[_Scan]:
        start = scan.position
        data = self.content(scan.state)
        longest = len(data) - start
        if directive.width is not None:
            longest = min(longest, directive.width)
        options: list[tuple[Expr, int]] = []
        prefix = sx.TRUE
        for length in range(1, longest + 1):
            prefix = sx.bool_and(prefix, sx.bool_not(_is_space(data[start + length - 1])))
            after = self._byte(scan, start + length)
            ends = sx.TRUE if length == directive.width or after is None else _is_space(after)
            options.append((sx.bool_and(prefix, ends), length))
        branches = self._fork(scan, options)
        for branch, length in branches:
            content = list(data[start : start + length])
            self._store(branch, directive, [*content, _ZERO_BYTE])
            branch.position = start + length
        return [branch for branch, _ in branches]

    def _scanset(self, scan: _Scan, directive: scanning.Directive) -> list[_Scan]:
        """`%[set]`: a maximal run of bytes in the set, with no leading whitespace skipped.

        A first byte outside the set is a matching failure that assigns nothing and leaves
        the byte unread, exactly as `%d` fails on a non-digit.
        """
        start = scan.position
        data = self.content(scan.state)
        longest = len(data) - start
        if directive.width is not None:
            longest = min(longest, directive.width)
        options: list[tuple[Expr, int]] = [
            (sx.bool_not(_in_scanset(data[start], directive)), 0)
        ]
        prefix = sx.TRUE
        for length in range(1, longest + 1):
            prefix = sx.bool_and(prefix, _in_scanset(data[start + length - 1], directive))
            after = self._byte(scan, start + length)
            ends = (
                sx.TRUE
                if length == directive.width or after is None
                else sx.bool_not(_in_scanset(after, directive))
            )
            options.append((sx.bool_and(prefix, ends), length))
        branches = self._fork(scan, options)
        for branch, length in branches:
            if length == 0:
                branch.result = branch.assigned  # nothing matched: a matching failure
                continue
            content = list(data[start : start + length])
            self._store(branch, directive, [*content, _ZERO_BYTE])
            branch.position = start + length
        return [branch for branch, _ in branches]

    def _characters(self, scan: _Scan, directive: scanning.Directive) -> _Scan:
        data = self.content(scan.state)
        start = scan.position
        content = list(data[start : start + (directive.width or 1)])
        self._store(scan, directive, content)
        scan.position = start + len(content)
        return scan

    def _radix(self, scan: _Scan, directive: scanning.Directive) -> list[_Scan]:
        """`%x`/`%o`: a hex or octal token, read like `%d` but over the radix's digits.

        The value wraps at 64 bits rather than saturating; a crackme's hex fits, and only
        the low `store_size` bytes are kept anyway.
        """
        data = self.content(scan.state)
        start = scan.position
        available = len(data) - start
        limit = available if directive.width is None else min(available, directive.width)
        base = directive.base
        first = data[start]
        sign = sx.bool_or(sx.equal(first, sx.const(0x2B, 8)), sx.equal(first, sx.const(0x2D, 8)))
        options: list[tuple[Expr, tuple[int, int]]] = []
        for signed in (0, 1):
            head = sign if signed else sx.bool_not(sign)
            if signed + 1 > limit:
                options.append((head, (signed, 0)))
                continue
            here = _is_radix_digit(data[start + signed], base)
            options.append((sx.bool_and(head, sx.bool_not(here)), (signed, 0)))
            digits = sx.TRUE
            for count in range(1, limit - signed + 1):
                seen = _is_radix_digit(data[start + signed + count - 1], base)
                digits = sx.bool_and(digits, seen)
                after = self._byte(scan, start + signed + count)
                if signed + count == directive.width or after is None:
                    ends = sx.TRUE
                else:
                    ends = sx.bool_not(_is_radix_digit(after, base))
                options.append((sx.bool_and(head, digits, ends), (signed, count)))
        result: list[_Scan] = []
        for branch, (signed, count) in self._fork(scan, options):
            if count == 0:
                branch.position = start + signed
                branch.result = branch.assigned
                result.append(branch)
                continue
            negative = sx.equal(first, sx.const(0x2D, 8)) if signed else sx.FALSE
            value = _radix_value(list(data[start + signed : start + signed + count]), base)
            value = sx.ite(negative, sx.negate(value), value)
            size = directive.store_size
            self._store(
                branch, directive, [sx.extract(value, 8 * index, 8) for index in range(size)]
            )
            branch.position = start + signed + count
            result.append(branch)
        return result

    def _decimal(self, scan: _Scan, directive: scanning.Directive) -> list[_Scan]:
        if directive.base != 10:
            return self._radix(scan, directive)
        data = self.content(scan.state)
        start = scan.position
        available = len(data) - start
        limit = available if directive.width is None else min(available, directive.width)
        first = data[start]
        sign = sx.bool_or(sx.equal(first, sx.const(0x2B, 8)), sx.equal(first, sx.const(0x2D, 8)))
        # (sign bytes, digit count): no digits is a matching failure, after which a sign
        # that was read stays consumed.
        options: list[tuple[Expr, tuple[int, int]]] = []
        for signed in (0, 1):
            head = sign if signed else sx.bool_not(sign)
            if signed + 1 > limit:
                options.append((head, (signed, 0)))
                continue
            digits = sx.TRUE
            options.append(
                (sx.bool_and(head, sx.bool_not(_is_digit(data[start + signed]))), (signed, 0))
            )
            for count in range(1, limit - signed + 1):
                digits = sx.bool_and(digits, _is_digit(data[start + signed + count - 1]))
                after = self._byte(scan, start + signed + count)
                if signed + count == directive.width or after is None:
                    ends = sx.TRUE
                else:
                    ends = sx.bool_not(_is_digit(after))
                options.append((sx.bool_and(head, digits, ends), (signed, count)))
        result: list[_Scan] = []
        values: dict[int, list[Expr]] = {}
        for branch, (signed, count) in self._fork(scan, options):
            if count == 0:
                branch.position = start + signed
                branch.result = branch.assigned
                result.append(branch)
                continue
            if signed not in values:
                negative = sx.equal(first, sx.const(0x2D, 8)) if signed else sx.FALSE
                values[signed] = _token_values(list(data[start + signed : start + limit]), negative)
            value = values[signed][count - 1]
            size = directive.store_size
            self._store(
                branch, directive, [sx.extract(value, 8 * index, 8) for index in range(size)]
            )
            branch.position = start + signed + count
            result.append(branch)
        return result


def _hex_digit(nibble: Expr, upper: bool) -> Expr:
    """One hex character of a symbolic nibble."""
    letter = sx.const(ord("A") if upper else ord("a"), 8)
    wide = sx.zero_extend(nibble, 8)
    return sx.ite(
        sx.unsigned_less(nibble, sx.const(10, 4)),
        sx.add(wide, sx.const(ord("0"), 8)),
        sx.add(sx.sub(wide, sx.const(10, 8)), letter),
    )

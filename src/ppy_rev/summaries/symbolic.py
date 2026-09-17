"""Symbolic models of C library functions.

Strings are bytes with NUL terminators. Where a string's end depends on symbolic bytes,
results are exact if-then-else chains over the possible terminator positions, bounded by
the first concrete terminator. Pointers, sizes, and descriptors must be determined by the
path condition; otherwise the call stops exploration as unsupported rather than guessing.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ppy_rev.abi import CallingConvention
from ppy_rev.execution.program import HEAP_SIZE, HEAP_START, STANDARD_STREAMS
from ppy_rev.ir.model import Origin
from ppy_rev.summaries.libc import canonical_name
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.executor import (
    Executor,
    Exited,
    ExternalOutcome,
    Failed,
    Returned,
    StopReason,
)
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.state import State

_NEWLINE = sx.const(0x0A, 8)
_ZERO_BYTE = sx.const(0, 8)


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

    def __init__(self, convention: CallingConvention, string_limit: int = 4096) -> None:
        self.convention = convention
        self.string_limit = string_limit
        self._models: dict[str, _Model] = {
            "strlen": self._strlen,
            "strcmp": self._strcmp,
            "strncmp": self._strncmp,
            "memcmp": self._memcmp,
            "memcpy": self._memcpy,
            "memmove": self._memmove,
            "memset": self._memset,
            "strcpy": self._strcpy,
            "strcspn": self._strcspn,
            "read": self._read,
            "fgets": self._fgets,
            "getchar": self._getchar,
            "puts": self._puts,
            "putchar": self._putchar,
            "fputs": self._fputs,
            "printf": self._printf,
            "__printf_chk": self._printf,
            "fflush": self._returns_zero,
            "setvbuf": self._returns_zero,
            "free": self._returns_zero,
            "exit": self._exit,
            "_exit": self._exit,
            "abort": self._abort,
            "__stack_chk_fail": self._abort,
            "malloc": self._malloc,
            "calloc": self._calloc,
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

    def _returns(self, call: _Call, value: Expr) -> list[ExternalOutcome]:
        outputs = dict(call.registers)
        result_register = self.convention.integer_returns[0]
        outputs[result_register] = value if value.width == 64 else sx.zero_extend(value, 64)
        return [Returned(call.state, outputs)]

    def _returns_zero(self, call: _Call) -> list[ExternalOutcome]:
        return self._returns(call, sx.const(0, 64))

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
        destination = self._concrete(call, call.arguments[0], "destination")
        source = self._concrete(call, call.arguments[1], "source")
        size = self._concrete(call, call.arguments[2], "size")
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
        for index, byte in enumerate(available):
            self._write(call, buffer + index, byte)
        io.stdin_reads.append((io.stdin_position, io.stdin_position + len(available), False))
        io.stdin_position += len(available)
        return self._returns(call, sx.const(len(available), 64))

    def _fgets(self, call: _Call) -> list[ExternalOutcome]:
        buffer = self._concrete(call, call.arguments[0], "buffer")
        size = self._concrete(call, sx.extract(call.arguments[1], 0, 32), "size")
        stream = self._concrete(call, call.arguments[2], "stream")
        if stream != STANDARD_STREAMS["stdin"]:
            raise _Unsupported(f"fgets from stream {stream:#x}")
        io = call.state.io
        remaining = io.stdin[io.stdin_position :]
        if size <= 0 or size > 0x7FFFFFFF or not remaining:
            return self._returns(call, sx.const(0, 64))
        taken = remaining[: size - 1]
        count = sx.const(len(taken), 64)
        for index in reversed(range(len(taken))):
            count = sx.ite(sx.equal(taken[index], _NEWLINE), sx.const(index + 1, 64), count)
        for index, byte in enumerate(taken):
            position = sx.const(index, 64)
            old = self._byte(call, buffer + index)
            terminator = sx.ite(sx.equal(position, count), _ZERO_BYTE, old)
            self._write(
                call, buffer + index, sx.ite(sx.unsigned_less(position, count), byte, terminator)
            )
        end = buffer + len(taken)
        old = self._byte(call, end)
        self._write(call, end, sx.ite(sx.equal(count, sx.const(len(taken), 64)), _ZERO_BYTE, old))
        io.stdin_reads.append((io.stdin_position, io.stdin_position + len(taken), True))
        consumed = call.executor.unique_value(call.state, count)
        if consumed is None:
            # The rest of stdin is only meaningful once the line length is known.
            io.stdin = io.stdin[: io.stdin_position]
            call.executor.approximate(
                call.state,
                "stdin after a symbolic-length fgets line is treated as empty",
                may_hide_paths=True,
            )
        else:
            io.stdin_position += consumed
        return self._returns(call, sx.const(buffer, 64))

    def _getchar(self, call: _Call) -> list[ExternalOutcome]:
        io = call.state.io
        if io.stdin_position >= len(io.stdin):
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

    def _malloc(self, call: _Call) -> list[ExternalOutcome]:
        size = self._concrete(call, call.arguments[0], "size")
        return self._returns(call, sx.const(self._allocate(call, size), 64))

    def _calloc(self, call: _Call) -> list[ExternalOutcome]:
        count = self._concrete(call, call.arguments[0], "count")
        size = self._concrete(call, call.arguments[1], "size")
        address = self._allocate(call, count * size)
        for index in range(count * size if address else 0):
            self._write(call, address + index, _ZERO_BYTE)
        return self._returns(call, sx.const(address, 64))

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
from ppy_rev.execution.memory import MemoryFaultError
from ppy_rev.execution.program import CTYPE_POINTERS, HEAP_SIZE, HEAP_START, STANDARD_STREAMS
from ppy_rev.ir.model import Origin
from ppy_rev.solver.backend import Status
from ppy_rev.summaries import ctype, scanning
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
from ppy_rev.symbolic.state import ConstraintKind, State

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
            "strncpy": self._strncpy,
            "strcspn": self._strcspn,
            "read": self._read,
            "fgets": self._fgets,
            "gets": self._gets,
            "getchar": self._getchar,
            "puts": self._puts,
            "putchar": self._putchar,
            "fputs": self._fputs,
            "printf": self._printf,
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
            "calloc": self._calloc,
            "atoi": self._atoi,
            "atol": self._atol,
            "atoll": self._atol,
            "strtol": self._strtol,
            "strtoll": self._strtol,
            "scanf": self._scanf,
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

    def _gets(self, call: _Call) -> list[ExternalOutcome]:
        """A line without its newline, however long: bytes the program cannot hold crash it."""
        buffer = self._concrete(call, call.arguments[0], "buffer")
        io = call.state.io
        remaining = io.stdin[io.stdin_position :]
        if not remaining:
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
            io.stdin = io.stdin[: io.stdin_position]
            call.executor.approximate(
                call.state,
                "stdin after a symbolic-length gets line is treated as empty",
                may_hide_paths=True,
            )
        else:
            io.stdin_position += consumed + (consumed < len(remaining))
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

    def _scanf(self, call: _Call) -> list[ExternalOutcome]:
        """scanf over the symbolic stdin stream, forking where the input's shape decides.

        Every alternative (how a token ends, whether a conversion fails) becomes its own
        state with the condition that selects it, so positions in the stream stay concrete.
        Whitespace skipped by a directive is never visible to the program: an input that
        skips several whitespace bytes behaves exactly like one that skips a single byte
        of it, so only zero or one skipped byte is explored.
        """
        template = self._string_bytes(call, self._concrete(call, call.arguments[0], "format"))
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
            self._concrete(call, self._variadic(call, 1 + index), "pointer")
            for index in range(assignments)
        ]
        scanner = _Scanner(self, call, directives, destinations)
        return scanner.run()

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
    for index, (condition, tag) in enumerate(live):
        child = state if index == len(live) - 1 else state.fork(executor.new_state_id())
        if child is state and index:
            executor.renumber(child)
        executor.add_constraint(child, condition, ConstraintKind.LIBRARY, call.origin, note)
        if condition is not sx.TRUE and executor.feasible(child) is Status.UNSAT:
            continue
        chosen.append((child, tag))
    if len(chosen) > 1:
        for child, _ in chosen:
            child.decisions += 1
    return chosen


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
    ) -> None:
        self.libc = libc
        self.call = call
        self.directives = directives
        self.destinations = destinations

    def run(self) -> list[ExternalOutcome]:
        io = self.call.state.io
        pending = [_Scan(self.call.state, io.stdin_position)]
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
        if scan.position > io.stdin_position:
            io.stdin_reads.append((io.stdin_position, scan.position, False))
            io.stdin_position = scan.position
        outputs = dict(self.call.registers)
        result = (scan.result or 0) & 0xFFFFFFFF
        outputs[self.libc.convention.integer_returns[0]] = sx.const(result, 64)
        return Returned(scan.state, outputs)

    # -- stream ------------------------------------------------------------------------------

    def _byte(self, scan: _Scan, index: int) -> Expr | None:
        stdin = scan.state.io.stdin
        return stdin[index] if index < len(stdin) else None

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
        stdin = scan.state.io.stdin
        longest = len(stdin) - start
        if directive.width is not None:
            longest = min(longest, directive.width)
        options: list[tuple[Expr, int]] = []
        prefix = sx.TRUE
        for length in range(1, longest + 1):
            prefix = sx.bool_and(prefix, sx.bool_not(_is_space(stdin[start + length - 1])))
            after = self._byte(scan, start + length)
            ends = sx.TRUE if length == directive.width or after is None else _is_space(after)
            options.append((sx.bool_and(prefix, ends), length))
        branches = self._fork(scan, options)
        for branch, length in branches:
            content = list(stdin[start : start + length])
            self._store(branch, directive, [*content, _ZERO_BYTE])
            branch.position = start + length
        return [branch for branch, _ in branches]

    def _characters(self, scan: _Scan, directive: scanning.Directive) -> _Scan:
        stdin = scan.state.io.stdin
        start = scan.position
        content = list(stdin[start : start + (directive.width or 1)])
        self._store(scan, directive, content)
        scan.position = start + len(content)
        return scan

    def _decimal(self, scan: _Scan, directive: scanning.Directive) -> list[_Scan]:
        stdin = scan.state.io.stdin
        start = scan.position
        available = len(stdin) - start
        limit = available if directive.width is None else min(available, directive.width)
        first = stdin[start]
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
                (sx.bool_and(head, sx.bool_not(_is_digit(stdin[start + signed]))), (signed, 0))
            )
            for count in range(1, limit - signed + 1):
                digits = sx.bool_and(digits, _is_digit(stdin[start + signed + count - 1]))
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
                values[signed] = _token_values(
                    list(stdin[start + signed : start + limit]), negative
                )
            value = values[signed][count - 1]
            size = directive.store_size
            self._store(
                branch, directive, [sx.extract(value, 8 * index, 8) for index in range(size)]
            )
            branch.position = start + signed + count
            result.append(branch)
        return result

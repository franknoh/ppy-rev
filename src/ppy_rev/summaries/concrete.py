"""Concrete models of C library functions for the RevIR interpreter.

They operate on bytes and NUL terminators exactly as C does, never on Python strings.
Standard input is a fixed byte string; output is collected rather than printed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ppy_rev.abi import CallingConvention
from ppy_rev.execution.memory import ConcreteMemory
from ppy_rev.execution.program import CTYPE_POINTERS, HEAP_SIZE, HEAP_START, STANDARD_STREAMS
from ppy_rev.ir.model import mask
from ppy_rev.ir.semantics import to_signed
from ppy_rev.summaries import ctype, scanning
from ppy_rev.summaries.formatting import FormatError, format_printf
from ppy_rev.summaries.libc import canonical_name


class ProgramExitError(Exception):
    """The program terminated through exit or a fatal library call."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class UnsupportedLibraryCallError(Exception):
    pass


@dataclass(slots=True)
class ConcreteIO:
    stdin: bytes = b""
    stdin_position: int = 0
    stdout: bytearray = field(default_factory=bytearray)
    heap_next: int = HEAP_START


type _Handler = Callable[[list[int], ConcreteMemory], int]


class ConcreteLibc:
    """An `ExternalHandler` for the interpreter."""

    def __init__(self, convention: CallingConvention, io: ConcreteIO | None = None) -> None:
        self.convention = convention
        self.io = io or ConcreteIO()
        self._handlers: dict[str, _Handler] = {
            "strlen": self._strlen,
            "strcmp": self._strcmp,
            "strncmp": self._strncmp,
            "memcmp": self._memcmp,
            "memcpy": self._memcpy,
            "memmove": self._memcpy,
            "memset": self._memset,
            "strcpy": self._strcpy,
            "strncpy": self._strncpy,
            "strcspn": self._strcspn,
            "read": self._read,
            "fgets": self._fgets,
            "getchar": self._getchar,
            "puts": self._puts,
            "putchar": self._putchar,
            "fputs": self._fputs,
            "fflush": lambda arguments, memory: 0,
            "setbuf": lambda arguments, memory: 0,
            "setvbuf": lambda arguments, memory: 0,
            "printf": self._printf,
            "__printf_chk": self._printf_chk,
            "exit": self._exit,
            "_exit": self._exit,
            "abort": self._abort,
            "__stack_chk_fail": self._stack_check_failed,
            "malloc": self._malloc,
            "calloc": self._calloc,
            "free": lambda arguments, memory: 0,
            "atoi": self._atoi,
            "atol": self._atol,
            "atoll": self._atol,
            "strtol": self._strtol,
            "strtoll": self._strtol,
            "scanf": self._scanf,
            "toupper": lambda arguments, memory: self._case(ctype.to_upper, arguments),
            "tolower": lambda arguments, memory: self._case(ctype.to_lower, arguments),
            **{
                name: lambda arguments, memory, pointer=pointer: pointer
                for name, pointer in CTYPE_POINTERS.items()
            },
            **{
                name: lambda arguments, memory, flag=flag: self._classify(flag, arguments)
                for name, flag in ctype.CLASSIFIERS.items()
            },
        }
        self._registers: dict[str, int] = {}

    def __call__(
        self, name: str, registers: dict[str, int], memory: ConcreteMemory
    ) -> dict[str, int]:
        handler = self._handlers.get(canonical_name(name))
        if handler is None:
            raise KeyError(name)
        arguments = [registers.get(register, 0) for register in self.convention.integer_parameters]
        self._registers = registers
        result = handler(arguments, memory)
        returned = dict(registers)
        returned[self.convention.integer_returns[0]] = result & mask(64)
        return returned

    # -- strings and memory ----------------------------------------------------------------

    @staticmethod
    def _string(memory: ConcreteMemory, address: int, limit: int = 1 << 20) -> bytes:
        return memory.read_c_string(address, limit)

    def _strlen(self, arguments: list[int], memory: ConcreteMemory) -> int:
        return len(self._string(memory, arguments[0]))

    def _strcmp(self, arguments: list[int], memory: ConcreteMemory) -> int:
        left = self._string(memory, arguments[0]) + b"\0"
        right = self._string(memory, arguments[1]) + b"\0"
        return self._compare_terminated(left, right)

    def _strncmp(self, arguments: list[int], memory: ConcreteMemory) -> int:
        limit = arguments[2]
        left = self._string(memory, arguments[0], limit) + b"\0"
        right = self._string(memory, arguments[1], limit) + b"\0"
        return self._compare_terminated(left[:limit], right[:limit])

    @staticmethod
    def _compare_terminated(left: bytes, right: bytes) -> int:
        for a, b in zip(left, right, strict=False):
            if a != b:
                return (a - b) & 0xFFFFFFFF
            if a == 0:
                return 0
        return 0

    def _memcmp(self, arguments: list[int], memory: ConcreteMemory) -> int:
        size = arguments[2]
        for index in range(size):
            a = memory.read(arguments[0] + index, 1)[0]
            b = memory.read(arguments[1] + index, 1)[0]
            if a != b:
                return (a - b) & 0xFFFFFFFF
        return 0

    def _memcpy(self, arguments: list[int], memory: ConcreteMemory) -> int:
        memory.write(arguments[0], memory.read(arguments[1], arguments[2]))
        return arguments[0]

    def _memset(self, arguments: list[int], memory: ConcreteMemory) -> int:
        memory.write(arguments[0], bytes([arguments[1] & 0xFF]) * arguments[2])
        return arguments[0]

    def _strcpy(self, arguments: list[int], memory: ConcreteMemory) -> int:
        memory.write(arguments[0], self._string(memory, arguments[1]) + b"\0")
        return arguments[0]

    def _strncpy(self, arguments: list[int], memory: ConcreteMemory) -> int:
        size = arguments[2]
        source = self._string(memory, arguments[1], size)
        memory.write(arguments[0], source[:size] + b"\0" * (size - len(source[:size])))
        return arguments[0]

    def _strcspn(self, arguments: list[int], memory: ConcreteMemory) -> int:
        text = self._string(memory, arguments[0])
        rejected = set(self._string(memory, arguments[1]))
        for index, byte in enumerate(text):
            if byte in rejected:
                return index
        return len(text)

    # -- input -----------------------------------------------------------------------------

    def _read(self, arguments: list[int], memory: ConcreteMemory) -> int:
        descriptor, buffer, count = arguments[0] & 0xFFFFFFFF, arguments[1], arguments[2]
        if descriptor != 0:
            raise UnsupportedLibraryCallError(f"read from file descriptor {descriptor}")
        data = self.io.stdin[self.io.stdin_position : self.io.stdin_position + count]
        memory.write(buffer, data)
        self.io.stdin_position += len(data)
        return len(data)

    def _require_stream(self, stream: int, name: str) -> None:
        if stream != STANDARD_STREAMS[name]:
            raise UnsupportedLibraryCallError(f"stream {stream:#x} is not {name}")

    def _fgets(self, arguments: list[int], memory: ConcreteMemory) -> int:
        buffer, size, stream = arguments[0], arguments[1] & 0xFFFFFFFF, arguments[2]
        self._require_stream(stream, "stdin")
        if size <= 0 or size > 0x7FFFFFFF:
            return 0
        remaining = self.io.stdin[self.io.stdin_position :]
        if not remaining:
            return 0
        taken = remaining[: size - 1]
        newline = taken.find(b"\n")
        if newline >= 0:
            taken = taken[: newline + 1]
        memory.write(buffer, taken + b"\0")
        self.io.stdin_position += len(taken)
        return buffer

    def _getchar(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del arguments, memory
        if self.io.stdin_position >= len(self.io.stdin):
            return 0xFFFFFFFF
        byte = self.io.stdin[self.io.stdin_position]
        self.io.stdin_position += 1
        return byte

    def _scanf(self, arguments: list[int], memory: ConcreteMemory) -> int:
        try:
            directives = scanning.parse_format(self._string(memory, arguments[0]))
        except scanning.FormatError as error:
            raise UnsupportedLibraryCallError(f"scanf: {error}") from error
        io = self.io
        scanned = scanning.scan(directives, io.stdin[io.stdin_position :])
        io.stdin_position += scanned.consumed
        for index, assignment in enumerate(scanned.assignments):
            destination = self._variadic(arguments, 1 + index, memory)
            match assignment.content:
                case bytes() as content if (
                    assignment.directive.kind is scanning.DirectiveKind.STRING
                ):
                    memory.write(destination, content + b"\0")
                case bytes() as content:
                    memory.write(destination, content)
                case int() as value:
                    size = assignment.directive.store_size
                    memory.store(destination, value & mask(size * 8), size * 8)
        return scanned.result & 0xFFFFFFFF

    def _variadic(self, arguments: list[int], index: int, memory: ConcreteMemory) -> int:
        """Integer argument `index`, from its register or the caller's stack."""
        if index < len(arguments):
            return arguments[index]
        stack = self._registers[self.convention.stack_pointer]
        # Above the return address are the stack-passed arguments, in order.
        return memory.load(stack + 8 * (1 + index - len(arguments)), 64)

    # -- numbers and characters ------------------------------------------------------------

    def _atoi(self, arguments: list[int], memory: ConcreteMemory) -> int:
        return scanning.parse_long(self._string(memory, arguments[0])).value & 0xFFFFFFFF

    def _atol(self, arguments: list[int], memory: ConcreteMemory) -> int:
        return scanning.parse_long(self._string(memory, arguments[0])).value & mask(64)

    def _strtol(self, arguments: list[int], memory: ConcreteMemory) -> int:
        text, end_pointer, base = arguments[0], arguments[1], to_signed(arguments[2], 32)
        if base != 10:
            raise UnsupportedLibraryCallError(f"strtol with base {base}")
        number = scanning.parse_long(self._string(memory, text))
        if end_pointer:
            memory.store(end_pointer, text + number.end, 64)
        return number.value & mask(64)

    @staticmethod
    def _case(mapping: Callable[[int], int], arguments: list[int]) -> int:
        character = to_signed(arguments[0] & 0xFFFFFFFF, 32)
        if not ctype.FIRST <= character <= ctype.LAST:
            return character & 0xFFFFFFFF
        return mapping(character) & 0xFFFFFFFF

    @staticmethod
    def _classify(flag: int, arguments: list[int]) -> int:
        character = to_signed(arguments[0] & 0xFFFFFFFF, 32)
        if not ctype.FIRST <= character <= ctype.LAST:
            raise UnsupportedLibraryCallError(f"character class of {character} is undefined")
        return ctype.classification(character) & flag

    # -- output ----------------------------------------------------------------------------

    def _puts(self, arguments: list[int], memory: ConcreteMemory) -> int:
        text = self._string(memory, arguments[0])
        self.io.stdout += text + b"\n"
        return len(text) + 1

    def _putchar(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        self.io.stdout.append(arguments[0] & 0xFF)
        return arguments[0] & 0xFF

    def _fputs(self, arguments: list[int], memory: ConcreteMemory) -> int:
        if arguments[1] != STANDARD_STREAMS["stderr"]:
            self._require_stream(arguments[1], "stdout")
            self.io.stdout += self._string(memory, arguments[0])
        return 1

    def _format(self, format_address: int, values: list[int], memory: ConcreteMemory) -> int:
        try:
            text = format_printf(self._string(memory, format_address), values, memory)
        except FormatError as error:
            raise UnsupportedLibraryCallError(str(error)) from error
        self.io.stdout += text
        return len(text)

    def _printf(self, arguments: list[int], memory: ConcreteMemory) -> int:
        # Only register-passed variadic arguments are modeled; formats needing more fail.
        return self._format(arguments[0], arguments[1:], memory)

    def _printf_chk(self, arguments: list[int], memory: ConcreteMemory) -> int:
        return self._format(arguments[1], arguments[2:], memory)

    # -- process ---------------------------------------------------------------------------

    def _exit(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        status = arguments[0] & 0xFF
        raise ProgramExitError(status, f"exit({status})")

    def _abort(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del arguments, memory
        raise ProgramExitError(134, "abort()")

    def _stack_check_failed(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del arguments, memory
        raise ProgramExitError(134, "stack smashing detected")

    def _malloc(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        size = max(1, arguments[0])
        address = self.io.heap_next
        if address + size > HEAP_START + HEAP_SIZE:
            return 0
        self.io.heap_next = (address + size + 31) & ~15
        return address

    def _calloc(self, arguments: list[int], memory: ConcreteMemory) -> int:
        size = arguments[0] * arguments[1]
        address = self._malloc([size], memory)
        if address:
            memory.write(address, bytes(size))
        return address

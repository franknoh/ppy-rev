"""Concrete models of C library functions for the RevIR interpreter.

They operate on bytes and NUL terminators exactly as C does, never on Python strings.
Standard input is a fixed byte string; output is collected rather than printed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ppy_rev.abi import CallingConvention
from ppy_rev.execution.memory import ConcreteMemory
from ppy_rev.execution.program import (
    CTYPE_POINTERS,
    ERRNO_ADDRESS,
    FILE_HANDLE_STEP,
    FILE_HANDLES,
    HEAP_SIZE,
    HEAP_START,
    STANDARD_STREAMS,
)
from ppy_rev.ir.model import mask
from ppy_rev.ir.semantics import to_signed
from ppy_rev.summaries import ctype, cxx, scanning
from ppy_rev.summaries.formatting import FormatError, format_printf
from ppy_rev.summaries.glibc_random import UNSEEDED, RandomState, advance, seeded
from ppy_rev.summaries.libc import canonical_name

_PTRACE_TRACEME = 0


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
    random: RandomState = UNSEEDED
    traced: bool = False
    """Whether a debugger traces the program, so `ptrace(PTRACE_TRACEME)` fails."""
    files: dict[str, bytes] = field(default_factory=dict[str, bytes])
    """What each file the program opens contains."""
    open_files: dict[int, str] = field(default_factory=dict[int, str])
    file_positions: dict[int, int] = field(default_factory=dict[int, int])


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
            "strchr": self._strchr,
            "std::getline": self._getline,
            "std::string::string": self._string_new,
            "std::string::_M_local_data": lambda arguments, memory: arguments[0] + cxx.BUFFER,
            "std::string::_M_data=": self._string_set_data,
            "std::string::_M_set_length": self._string_set_length,
            "std::string::_M_capacity": self._string_set_capacity,
            "std::string::_S_copy_chars": self._string_copy_chars,
            "std::string::_M_create": self._string_create,
            "std::string::operator+=": self._string_append,
            "std::string::~string": lambda arguments, memory: 0,
            "std::string::size": lambda arguments, memory: self._string_field(
                memory, arguments[0], cxx.SIZE
            ),
            "std::string::data": lambda arguments, memory: self._string_field(
                memory, arguments[0], cxx.DATA
            ),
            "std::string::empty": lambda arguments, memory: int(
                self._string_field(memory, arguments[0], cxx.SIZE) == 0
            ),
            "std::ostream::operator<<": self._ostream_write,
            "std::istream::operator>>": self._istream_read,
            "std::endl": self._endl,
            "std::string::at": lambda arguments, memory: (
                (self._string_field(memory, arguments[0], cxx.DATA) + arguments[1]) & mask(64)
            ),
            "std::string::begin": lambda arguments, memory: self._string_field(
                memory, arguments[0], cxx.DATA
            ),
            "std::string::end": lambda arguments, memory: (
                self._string_field(memory, arguments[0], cxx.DATA)
                + self._string_field(memory, arguments[0], cxx.SIZE)
            ),
            "ptrace": self._ptrace,
            "read": self._read,
            "fgets": self._fgets,
            "fopen": self._fopen,
            "fclose": self._fclose,
            "feof": self._feof,
            "fread": self._fread,
            "fgetc": self._fgetc,
            "getc": self._fgetc,
            "fputc": self._fputc,
            "putc": self._fputc,
            "fwrite": self._fwrite,
            "strcat": self._strcat,
            "strncat": self._strncat,
            "strstr": self._strstr,
            "fseek": self._fseek,
            "ftell": self._ftell,
            "rewind": self._rewind,
            "gets": self._gets,
            "srand": self._srand,
            "rand": self._rand,
            "getchar": self._getchar,
            "puts": self._puts,
            "putchar": self._putchar,
            "fputs": self._fputs,
            "fflush": lambda arguments, memory: 0,
            "setbuf": lambda arguments, memory: 0,
            "setvbuf": lambda arguments, memory: 0,
            "printf": self._printf,
            "sprintf": self._sprintf,
            "snprintf": self._snprintf,
            "__printf_chk": self._printf_chk,
            "exit": self._exit,
            "_exit": self._exit,
            "abort": self._abort,
            "__stack_chk_fail": self._stack_check_failed,
            "malloc": self._malloc,
            "calloc": self._calloc,
            "free": lambda arguments, memory: 0,
            "operator new": self._malloc,
            "operator delete": lambda arguments, memory: 0,
            "std::ios_base::Init::Init": lambda arguments, memory: 0,
            "std::ios_base::Init::~Init": lambda arguments, memory: 0,
            "__cxa_atexit": lambda arguments, memory: 0,
            "__cxa_guard_acquire": self._guard_acquire,
            "__cxa_guard_release": self._guard_release,
            "__cxa_guard_abort": lambda arguments, memory: 0,
            "atoi": self._atoi,
            "atol": self._atol,
            "atoll": self._atol,
            "strtol": self._strtol,
            "strtoll": self._strtol,
            "scanf": self._scanf,
            "fscanf": self._fscanf,
            "__errno_location": lambda arguments, memory: ERRNO_ADDRESS,
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

    def _strchr(self, arguments: list[int], memory: ConcreteMemory) -> int:
        text = self._string(memory, arguments[0])
        wanted = arguments[1] & 0xFF
        if wanted == 0:
            return arguments[0] + len(text)
        index = text.find(wanted)
        return 0 if index < 0 else arguments[0] + index

    def _ptrace(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        if arguments[0] != _PTRACE_TRACEME:
            raise UnsupportedLibraryCallError(f"ptrace request {arguments[0]}")
        return mask(64) if self.io.traced else 0

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

    # -- files -----------------------------------------------------------------------------

    def _fopen(self, arguments: list[int], memory: ConcreteMemory) -> int:
        name = self._string(memory, arguments[0]).decode("latin-1")
        handle = FILE_HANDLES + FILE_HANDLE_STEP * len(self.io.open_files)
        self.io.open_files[handle] = name
        self.io.file_positions[handle] = 0
        return handle

    def _fclose(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        self.io.file_positions.pop(arguments[0], None)
        return 0

    def _feof(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        content, position = self._stream(arguments[0])
        return int(position >= len(content))

    def _stream(self, stream: int) -> tuple[bytes, int]:
        """What a stream still holds, and how far it has been read."""
        if stream == STANDARD_STREAMS["stdin"]:
            return self.io.stdin, self.io.stdin_position
        name = self.io.open_files.get(stream)
        if name is None:
            raise UnsupportedLibraryCallError(f"stream {stream:#x} was not opened here")
        return self.io.files.get(name, b""), self.io.file_positions.get(stream, 0)

    def _advance(self, stream: int, count: int) -> None:
        if stream == STANDARD_STREAMS["stdin"]:
            self.io.stdin_position += count
        else:
            self.io.file_positions[stream] = self.io.file_positions.get(stream, 0) + count

    def _fgets(self, arguments: list[int], memory: ConcreteMemory) -> int:
        buffer, size, stream = arguments[0], arguments[1] & 0xFFFFFFFF, arguments[2]
        if size <= 0 or size > 0x7FFFFFFF:
            return 0
        content, position = self._stream(stream)
        remaining = content[position:]
        if not remaining:
            return 0
        taken = remaining[: size - 1]
        newline = taken.find(b"\n")
        if newline >= 0:
            taken = taken[: newline + 1]
        memory.write(buffer, taken + b"\0")
        self._advance(stream, len(taken))
        return buffer

    # -- the C++ standard library ----------------------------------------------------------

    @staticmethod
    def _string_field(memory: ConcreteMemory, object_at: int, offset: int) -> int:
        return memory.load(object_at + offset, 64)

    def _store_string(self, memory: ConcreteMemory, object_at: int, content: bytes) -> None:
        if len(content) > cxx.SMALL:
            buffer = self._allocate(len(content) + 1)
            if not buffer:
                raise UnsupportedLibraryCallError("a std::string longer than the heap can hold")
            memory.store(object_at + cxx.CAPACITY, len(content), 64)
        else:
            buffer = object_at + cxx.BUFFER
        memory.store(object_at + cxx.DATA, buffer, 64)
        memory.store(object_at + cxx.SIZE, len(content), 64)
        memory.write(buffer, content + b"\0")

    def _string_set_data(self, arguments: list[int], memory: ConcreteMemory) -> int:
        """`_M_data(p)`, and the `_Alloc_hider` constructor that is the same store."""
        memory.store(arguments[0] + cxx.DATA, arguments[1], 64)
        return arguments[0]

    def _string_set_length(self, arguments: list[int], memory: ConcreteMemory) -> int:
        """`_M_set_length(n)`: the length, and the terminator the string keeps after it."""
        object_at, length = arguments[0], arguments[1]
        memory.store(object_at + cxx.SIZE, length, 64)
        memory.write(self._string_field(memory, object_at, cxx.DATA) + length, b"\0")
        return object_at

    def _string_set_capacity(self, arguments: list[int], memory: ConcreteMemory) -> int:
        memory.store(arguments[0] + cxx.CAPACITY, arguments[1], 64)
        return arguments[0]

    def _string_copy_chars(self, arguments: list[int], memory: ConcreteMemory) -> int:
        """`_S_copy_chars(destination, first, last)`: the copy a construction ends with."""
        destination, first, last = arguments[0], arguments[1], arguments[2]
        memory.write(destination, memory.read(first, max(0, last - first)))
        return destination

    def _string_create(self, arguments: list[int], memory: ConcreteMemory) -> int:
        """`_M_create(capacity, old)`: a buffer for a string too long to live in the object."""
        wanted = memory.load(arguments[1], 64)
        buffer = self._allocate(wanted + 1)
        if not buffer:
            raise UnsupportedLibraryCallError("a std::string longer than the heap can hold")
        memory.store(arguments[1], wanted, 64)
        return buffer

    def _string_append(self, arguments: list[int], memory: ConcreteMemory) -> int:
        """`s += c`: one character onto the end, moving to the heap if it no longer fits."""
        object_at, character = arguments[0], arguments[1] & 0xFF
        data = self._string_field(memory, object_at, cxx.DATA)
        length = self._string_field(memory, object_at, cxx.SIZE)
        self._store_string(memory, object_at, memory.read(data, length) + bytes([character]))
        return object_at

    def _string_new(self, arguments: list[int], memory: ConcreteMemory) -> int:
        source = arguments[1]
        content = self._string(memory, source) if source else b""
        self._store_string(memory, arguments[0], content)
        return arguments[0]

    def _ostream_write(self, arguments: list[int], memory: ConcreteMemory) -> int:
        text = arguments[1]
        if text:
            self.io.stdout.extend(self._string(memory, text))
        return arguments[0]

    def _endl(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        self.io.stdout.append(0x0A)
        return arguments[0]

    def _istream_read(self, arguments: list[int], memory: ConcreteMemory) -> int:
        remaining = self.io.stdin[self.io.stdin_position :]
        token = remaining.lstrip(b" \t\n\r\f\v")
        skipped = len(remaining) - len(token)
        end = len(token)
        for index, byte in enumerate(token):
            if byte in b" \t\n\r\f\v":
                end = index
                break
        self._store_string(memory, arguments[1], token[:end])
        self.io.stdin_position += skipped + end
        return arguments[0]

    def _getline(self, arguments: list[int], memory: ConcreteMemory) -> int:
        remaining = self.io.stdin[self.io.stdin_position :]
        if not remaining:
            return arguments[0]
        newline = remaining.find(b"\n")
        content = remaining if newline < 0 else remaining[:newline]
        self._store_string(memory, arguments[1], content)
        self.io.stdin_position += len(content) + (0 if newline < 0 else 1)
        return arguments[0]

    def _seek(self, stream: int, offset: int, whence: int) -> int:
        content, position = self._stream(stream)
        start = {0: 0, 1: position, 2: len(content)}.get(whence)
        if start is None:
            raise UnsupportedLibraryCallError(f"fseek with whence {whence}")
        target = max(0, min(len(content), start + to_signed(offset & mask(64), 64)))
        if stream == STANDARD_STREAMS["stdin"]:
            self.io.stdin_position = target
        else:
            self.io.file_positions[stream] = target
        return target

    def _fseek(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        self._seek(arguments[0], arguments[1], arguments[2] & 0xFFFFFFFF)
        return 0

    def _ftell(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        return self._stream(arguments[0])[1]

    def _rewind(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        self._seek(arguments[0], 0, 0)
        return 0

    def _fgetc(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        content, position = self._stream(arguments[0])
        if position >= len(content):
            return mask(32)  # EOF
        self._advance(arguments[0], 1)
        return content[position]

    def _fputc(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        self._write_stream(arguments[1], bytes([arguments[0] & 0xFF]))
        return arguments[0] & 0xFF

    def _fwrite(self, arguments: list[int], memory: ConcreteMemory) -> int:
        buffer, size, count = arguments[0], arguments[1], arguments[2]
        self._write_stream(arguments[3], memory.read(buffer, size * count))
        return count

    def _write_stream(self, stream: int, content: bytes) -> None:
        """Bytes the program writes: to the output it prints, or into the file it opened."""
        if stream in (STANDARD_STREAMS["stdout"], STANDARD_STREAMS["stderr"]):
            self.io.stdout += content
            return
        name = self.io.open_files.get(stream)
        if name is None:
            raise UnsupportedLibraryCallError(f"stream {stream:#x} was not opened here")
        position = self.io.file_positions.get(stream, 0)
        kept = self.io.files.get(name, b"")[:position] + content
        self.io.files[name] = kept
        self.io.file_positions[stream] = len(kept)

    def _strcat(self, arguments: list[int], memory: ConcreteMemory) -> int:
        destination, source = arguments[0], arguments[1]
        end = destination + len(self._string(memory, destination))
        memory.write(end, self._string(memory, source) + b"\0")
        return destination

    def _strncat(self, arguments: list[int], memory: ConcreteMemory) -> int:
        destination, source, limit = arguments[0], arguments[1], arguments[2]
        end = destination + len(self._string(memory, destination))
        memory.write(end, self._string(memory, source)[:limit] + b"\0")
        return destination

    def _strstr(self, arguments: list[int], memory: ConcreteMemory) -> int:
        haystack = self._string(memory, arguments[0])
        needle = self._string(memory, arguments[1])
        found = haystack.find(needle)
        return 0 if found < 0 else arguments[0] + found

    def _fread(self, arguments: list[int], memory: ConcreteMemory) -> int:
        buffer, size, count, stream = arguments[0], arguments[1], arguments[2], arguments[3]
        wanted = size * count
        content, position = self._stream(stream)
        taken = content[position : position + wanted]
        memory.write(buffer, taken)
        self._advance(stream, len(taken))
        return len(taken) // size if size else 0

    def _srand(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        self.io.random = seeded(arguments[0] & 0xFFFFFFFF)
        return 0

    def _rand(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del arguments, memory
        self.io.random, value = advance(self.io.random)
        return value

    def _gets(self, arguments: list[int], memory: ConcreteMemory) -> int:
        remaining = self.io.stdin[self.io.stdin_position :]
        if not remaining:
            return 0
        newline = remaining.find(b"\n")
        line = remaining if newline < 0 else remaining[:newline]
        memory.write(arguments[0], line + b"\0")
        self.io.stdin_position += len(line) + (newline >= 0)
        return arguments[0]

    def _getchar(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del arguments, memory
        if self.io.stdin_position >= len(self.io.stdin):
            return 0xFFFFFFFF
        byte = self.io.stdin[self.io.stdin_position]
        self.io.stdin_position += 1
        return byte

    def _scanf(self, arguments: list[int], memory: ConcreteMemory) -> int:
        return self._scan(arguments, memory, format_index=0, stream=STANDARD_STREAMS["stdin"])

    def _fscanf(self, arguments: list[int], memory: ConcreteMemory) -> int:
        return self._scan(arguments, memory, format_index=1, stream=arguments[0])

    def _scan(
        self, arguments: list[int], memory: ConcreteMemory, format_index: int, stream: int
    ) -> int:
        try:
            directives = scanning.parse_format(self._string(memory, arguments[format_index]))
        except scanning.FormatError as error:
            raise UnsupportedLibraryCallError(f"scanf: {error}") from error
        content, position = self._stream(stream)
        scanned = scanning.scan(directives, content[position:])
        self._advance(stream, scanned.consumed)
        for index, assignment in enumerate(scanned.assignments):
            destination = self._variadic(arguments, format_index + 1 + index, memory)
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

    def _sprintf(self, arguments: list[int], memory: ConcreteMemory) -> int:
        return self._format_into(arguments[0], arguments[1], arguments[2:], memory, None)

    def _snprintf(self, arguments: list[int], memory: ConcreteMemory) -> int:
        return self._format_into(arguments[0], arguments[2], arguments[3:], memory, arguments[1])

    def _format_into(
        self,
        buffer: int,
        template: int,
        values: list[int],
        memory: ConcreteMemory,
        limit: int | None,
    ) -> int:
        try:
            text = format_printf(self._string(memory, template), values, memory)
        except FormatError as error:
            raise UnsupportedLibraryCallError(str(error)) from error
        written = text if limit is None else text[: max(0, limit - 1)]
        memory.write(buffer, written + b"\0")
        return len(text)

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

    def _allocate(self, size: int) -> int:
        address = self.io.heap_next
        if address + max(1, size) > HEAP_START + HEAP_SIZE:
            return 0
        self.io.heap_next = (address + max(1, size) + 31) & ~15
        return address

    def _malloc(self, arguments: list[int], memory: ConcreteMemory) -> int:
        del memory
        return self._allocate(arguments[0])

    def _guard_acquire(self, arguments: list[int], memory: ConcreteMemory) -> int:
        """`__cxa_guard_acquire`: whether this function-local static still needs building."""
        return int(memory.read(arguments[0], 1)[0] == 0)

    def _guard_release(self, arguments: list[int], memory: ConcreteMemory) -> int:
        """`__cxa_guard_release`: the static is built, so the next call skips it."""
        memory.write(arguments[0], b"\x01")
        return 0

    def _calloc(self, arguments: list[int], memory: ConcreteMemory) -> int:
        size = arguments[0] * arguments[1]
        address = self._malloc([size], memory)
        if address:
            memory.write(address, bytes(size))
        return address

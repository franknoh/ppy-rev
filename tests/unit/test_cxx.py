"""The C++ models — a `std::string` read from a line, and stream output — in both engines."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ppy_rev.abi import SYSV_X86_64
from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.ir.model import Endianness, Origin
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.summaries import cxx
from ppy_rev.summaries.concrete import ConcreteIO, ConcreteLibc
from ppy_rev.summaries.libc import canonical_name
from ppy_rev.summaries.symbolic import SymbolicLibc
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.evaluate import evaluate
from ppy_rev.symbolic.executor import Executor, Goal, Returned
from ppy_rev.symbolic.memory import SymbolicMemory
from ppy_rev.symbolic.state import State, SymbolicIO
from support.revir import module_for

REGISTERS = tuple((name, 64) for name in ("RAX", "RCX", "RDX", "RSP", "RSI", "RDI", "R8", "R9"))
DATA = 0x10000
STREAM = DATA + 0x40
OBJECT = DATA + 0x100
TEXT = DATA + 0x200
MODULE = module_for(registers=REGISTERS)
lines = st.binary(min_size=0, max_size=40).map(lambda data: data.replace(b"\n", b"?"))


def _memory() -> ConcreteMemory:
    memory = ConcreteMemory(Endianness.LITTLE)
    memory.map(Mapping("data", DATA, 0x1000, True, True, None))
    memory.map(Mapping("[heap]", 0x5555_A000_0000, 0x1000, True, True, None))
    return memory


def _concrete(name: str, arguments: list[int], stdin: bytes) -> tuple[int, ConcreteMemory, bytes]:
    memory = _memory()
    io = ConcreteIO(stdin=stdin)
    registers = dict(zip(SYSV_X86_64.integer_parameters, arguments, strict=False))
    result = ConcreteLibc(SYSV_X86_64, io)(canonical_name(name), registers, memory)
    return result["RAX"], memory, bytes(io.stdout)


def _symbolic(
    name: str, arguments: list[int], stdin: bytes
) -> tuple[State, dict[str, int], Returned]:
    executor = Executor(MODULE, Z3Backend(), Goal())
    assignment = {f"in_{index}": byte for index, byte in enumerate(stdin)}
    symbols = tuple(sx.symbol(f"in_{index}", 8) for index in range(len(stdin)))
    state = State(id=1, frames=[], memory=SymbolicMemory(_memory()), io=SymbolicIO(stdin=symbols))
    outcomes = SymbolicLibc(SYSV_X86_64).call(
        executor,
        state,
        canonical_name(name),
        {
            register: sx.const(value, 64)
            for register, value in zip(SYSV_X86_64.integer_parameters, arguments, strict=False)
        },
        Origin(0, 0),
    )
    assert outcomes is not None
    # A model may split (a std::string is short or it is not); one split holds for this input.
    (outcome,) = [
        item
        for item in outcomes
        if isinstance(item, Returned)
        and all(evaluate(entry.condition, assignment) for entry in item.state.constraints)
    ]
    return outcome.state, assignment, outcome


def _stored(state: State, assignment: dict[str, int], address: int, width: int = 64) -> int:
    return evaluate(state.memory.load(address, width), assignment)


@settings(max_examples=60, deadline=None)
@given(lines)
def test_getline_stores_the_line_the_same_way_in_both_models(line: bytes) -> None:
    stdin = line + b"\nrest"
    result, memory, _ = _concrete("getline<char>", [STREAM, OBJECT], stdin)
    assert result == STREAM
    assert memory.load(OBJECT + cxx.SIZE, 64) == len(line)
    pointer = memory.load(OBJECT + cxx.DATA, 64)
    assert memory.read(pointer, len(line)) == line
    assert (pointer == OBJECT + cxx.BUFFER) == (len(line) <= cxx.SMALL)

    state, assignment, outcome = _symbolic("getline<char>", [STREAM, OBJECT], stdin)
    assert evaluate(outcome.outputs["RAX"], assignment) == STREAM
    assert _stored(state, assignment, OBJECT + cxx.SIZE) == len(line)
    symbolic_pointer = _stored(state, assignment, OBJECT + cxx.DATA)
    assert symbolic_pointer == pointer
    for index, byte in enumerate(line):
        assert _stored(state, assignment, pointer + index, 8) == byte
    assert _stored(state, assignment, pointer + len(line), 8) == 0


def test_size_and_data_read_back_what_getline_wrote() -> None:
    stdin = b"open sesame\n"
    _, memory, _ = _concrete("getline<char>", [STREAM, OBJECT], stdin)
    io = ConcreteIO()
    libc = ConcreteLibc(SYSV_X86_64, io)
    registers = dict(zip(SYSV_X86_64.integer_parameters, [OBJECT], strict=False))
    assert libc("std::string::size", dict(registers), memory)["RAX"] == len(b"open sesame")
    assert libc("std::string::data", dict(registers), memory)["RAX"] == OBJECT + cxx.BUFFER
    assert libc("std::string::empty", dict(registers), memory)["RAX"] == 0


def test_stream_output_is_what_the_program_printed() -> None:
    memory = _memory()
    memory.write(TEXT, b"Correct!\0")
    io = ConcreteIO()
    registers = dict(zip(SYSV_X86_64.integer_parameters, [STREAM, TEXT], strict=False))
    result = ConcreteLibc(SYSV_X86_64, io)("std::ostream::operator<<", registers, memory)
    assert result["RAX"] == STREAM
    assert bytes(io.stdout) == b"Correct!"

    state, assignment, outcome = _symbolic("operator<<", [STREAM, TEXT], b"")
    state.memory.write_byte(TEXT, sx.const(0x43, 8))
    assert evaluate(outcome.outputs["RAX"], assignment) == STREAM


def test_a_long_line_goes_to_the_heap() -> None:
    line = b"x" * 30
    _, memory, _ = _concrete("getline<char>", [STREAM, OBJECT], line + b"\n")
    pointer = memory.load(OBJECT + cxx.DATA, 64)
    assert pointer != OBJECT + cxx.BUFFER
    assert memory.read(pointer, len(line)) == line
    assert memory.load(OBJECT + cxx.CAPACITY, 64) == len(line)


def test_demangled_names_map_to_the_models() -> None:
    assert canonical_name("getline<char,std::char_traits<char>,std::allocator<char>>") == (
        "std::getline"
    )
    assert canonical_name("operator<<") == "std::ostream::operator<<"
    assert canonical_name("~string") == "std::string::~string"
    assert canonical_name("strlen") == "strlen"  # a C name stays itself

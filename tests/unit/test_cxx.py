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
from ppy_rev.summaries.cxx import from_symbol
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
    result, memory, _ = _concrete("std::getline", [STREAM, OBJECT], stdin)
    assert result == STREAM
    assert memory.load(OBJECT + cxx.SIZE, 64) == len(line)
    pointer = memory.load(OBJECT + cxx.DATA, 64)
    assert memory.read(pointer, len(line)) == line
    assert (pointer == OBJECT + cxx.BUFFER) == (len(line) <= cxx.SMALL)

    state, assignment, outcome = _symbolic("std::getline", [STREAM, OBJECT], stdin)
    assert evaluate(outcome.outputs["RAX"], assignment) == STREAM
    assert _stored(state, assignment, OBJECT + cxx.SIZE) == len(line)
    symbolic_pointer = _stored(state, assignment, OBJECT + cxx.DATA)
    assert symbolic_pointer == pointer
    for index, byte in enumerate(line):
        assert _stored(state, assignment, pointer + index, 8) == byte
    assert _stored(state, assignment, pointer + len(line), 8) == 0


def test_size_and_data_read_back_what_getline_wrote() -> None:
    stdin = b"open sesame\n"
    _, memory, _ = _concrete("std::getline", [STREAM, OBJECT], stdin)
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

    state, assignment, outcome = _symbolic("std::ostream::operator<<", [STREAM, TEXT], b"")
    state.memory.write_byte(TEXT, sx.const(0x43, 8))
    assert evaluate(outcome.outputs["RAX"], assignment) == STREAM


def test_a_long_line_goes_to_the_heap() -> None:
    line = b"x" * 30
    _, memory, _ = _concrete("std::getline", [STREAM, OBJECT], line + b"\n")
    pointer = memory.load(OBJECT + cxx.DATA, 64)
    assert pointer != OBJECT + cxx.BUFFER
    assert memory.read(pointer, len(line)) == line
    assert memory.load(OBJECT + cxx.CAPACITY, 64) == len(line)


def test_indexing_and_iterators_point_into_the_string() -> None:
    _, memory, _ = _concrete("std::getline", [STREAM, OBJECT], b"sesame\n")
    io = ConcreteIO()
    libc = ConcreteLibc(SYSV_X86_64, io)

    def call(name: str, *arguments: int) -> int:
        registers = dict(zip(SYSV_X86_64.integer_parameters, arguments, strict=False))
        return libc(name, registers, memory)["RAX"]

    start = call("std::string::begin", OBJECT)
    assert start == OBJECT + cxx.BUFFER
    assert call("std::string::end", OBJECT) == start + len(b"sesame")
    assert memory.read(call("std::string::at", OBJECT, 2), 1) == b"s"


def test_models_are_chosen_by_the_linker_symbol_not_the_demangled_name() -> None:
    """`size` and `data` are ordinary C names; only the mangled symbol is unambiguous."""
    string = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE"
    assert from_symbol("_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istream") is None
    assert from_symbol(
        f"_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RN{string[3:]}"
    ) == ("std::getline")
    assert from_symbol(f"{string}4sizeEv") == "std::string::size"
    assert from_symbol(f"{string}ixEm") == "std::string::at"
    assert from_symbol("_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc") == (
        "std::ostream::operator<<"
    )
    assert from_symbol("_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_") == "std::endl"
    assert from_symbol("size") is None  # a C function keeps its own meaning
    assert canonical_name("strlen") == "strlen"


def test_a_token_is_read_up_to_whitespace() -> None:
    _, memory, _ = _concrete("std::istream::operator>>", [STREAM, OBJECT], b"  hunter2 rest\n")
    assert memory.load(OBJECT + cxx.SIZE, 64) == len(b"hunter2")
    assert memory.read(memory.load(OBJECT + cxx.DATA, 64), 7) == b"hunter2"

    state, assignment, _ = _symbolic("std::istream::operator>>", [STREAM, OBJECT], b"hi there\n")
    assert _stored(state, assignment, OBJECT + cxx.SIZE) == 2


def test_the_runtime_helpers_a_constructor_calls() -> None:
    """`operator new`, the iostream setup, and a function-local static's guard.

    A C++ program runs all of these before it reaches anything a challenge is about, so
    both engines have to agree on them or the answer is checked against a program that
    starts differently.
    """
    assert from_symbol("_Znwm") == "operator new"
    assert from_symbol("_ZdlPvm") == "operator delete"
    assert from_symbol("_ZNSt8ios_base4InitC1Ev") == "std::ios_base::Init::Init"

    guard = OBJECT + 0x80
    allocated, memory, _ = _concrete("operator new", [32], b"")
    assert memory.mapping_at(allocated) is not None
    assert _concrete("std::ios_base::Init::Init", [STREAM], b"")[0] == 0

    libc = ConcreteLibc(SYSV_X86_64, ConcreteIO())
    registers = dict(zip(SYSV_X86_64.integer_parameters, [guard], strict=False))
    assert libc("__cxa_guard_acquire", dict(registers), memory)["RAX"] == 1
    assert libc("__cxa_guard_release", dict(registers), memory)["RAX"] == 0
    assert libc("__cxa_guard_acquire", dict(registers), memory)["RAX"] == 0

    state, model, returned = _symbolic("__cxa_guard_acquire", [guard], b"")
    assert evaluate(returned.outputs["RAX"], model) == 1
    assert evaluate(state.memory.read_byte(guard), model) == 0


def test_the_string_members_a_construction_is_made_of() -> None:
    """`std::string s = "text"` at -O0 is a chain of these, one call each.

    Both engines have to end with the same object: a `data` pointer at the buffer, the
    length, and a terminator after it — the layout optimized code reads directly.
    """
    assert from_symbol(
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_M_local_dataEv"
    ) == ("std::string::_M_local_data")
    assert from_symbol(
        "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_M_set_lengthEm"
    ) == ("std::string::_M_set_length")

    memory = _memory()
    memory.write(TEXT, b"six!!!\0")
    libc = ConcreteLibc(SYSV_X86_64, ConcreteIO())

    def call(name: str, *arguments: int) -> int:
        registers = dict(zip(SYSV_X86_64.integer_parameters, arguments, strict=False))
        return libc(name, registers, memory)["RAX"]

    buffer = call("std::string::_M_local_data", OBJECT)
    assert buffer == OBJECT + cxx.BUFFER
    call("std::string::_M_data=", OBJECT, buffer)
    call("std::string::_S_copy_chars", buffer, TEXT, TEXT + 6)
    call("std::string::_M_set_length", OBJECT, 6)
    assert call("std::string::size", OBJECT) == 6
    assert memory.read_c_string(call("std::string::data", OBJECT)) == b"six!!!"
    call("std::string::operator+=", OBJECT, ord("?"))
    assert call("std::string::size", OBJECT) == 7
    assert memory.read_c_string(call("std::string::data", OBJECT)) == b"six!!!?"

    executor = Executor(MODULE, Z3Backend(), Goal())
    image = _memory()
    image.write(TEXT, b"six!!!\0")
    state = State(id=1, frames=[], memory=SymbolicMemory(image), io=SymbolicIO())
    symbolic = SymbolicLibc(SYSV_X86_64)

    def call_symbolic(name: str, *arguments: int) -> int:
        outcomes = symbolic.call(
            executor,
            state,
            name,
            {
                register: sx.const(value, 64)
                for register, value in zip(SYSV_X86_64.integer_parameters, arguments, strict=False)
            },
            Origin(0, 0),
        )
        assert outcomes is not None
        (outcome,) = outcomes
        assert isinstance(outcome, Returned), outcome
        return evaluate(outcome.outputs["RAX"], {})

    buffer = call_symbolic("std::string::_M_local_data", OBJECT)
    call_symbolic("std::string::_M_data=", OBJECT, buffer)
    call_symbolic("std::string::_S_copy_chars", buffer, TEXT, TEXT + 6)
    call_symbolic("std::string::_M_set_length", OBJECT, 6)
    assert call_symbolic("std::string::size", OBJECT) == 6
    call_symbolic("std::string::operator+=", OBJECT, ord("?"))
    assert call_symbolic("std::string::size", OBJECT) == 7
    data = call_symbolic("std::string::data", OBJECT)
    for offset in range(8):
        assert (
            evaluate(state.memory.read_byte(data + offset), {})
            == memory.read(OBJECT + cxx.BUFFER + offset, 1)[0]
        ), offset

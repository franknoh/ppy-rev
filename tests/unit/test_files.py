"""A file the program opens is an input: the same bytes in the solver and the interpreter."""

from __future__ import annotations

from ppy_rev.abi import SYSV_X86_64
from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.execution.program import FILE_HANDLES, STANDARD_STREAMS
from ppy_rev.ir.model import Endianness, Origin
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.summaries.concrete import ConcreteIO, ConcreteLibc, UnsupportedLibraryCallError
from ppy_rev.summaries.symbolic import SymbolicLibc
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.evaluate import evaluate
from ppy_rev.symbolic.executor import Executor, Failed, Goal, Returned
from ppy_rev.symbolic.memory import SymbolicMemory
from ppy_rev.symbolic.state import State, SymbolicIO
from support.revir import module_for

REGISTERS = tuple((name, 64) for name in ("RAX", "RCX", "RDX", "RSP", "RSI", "RDI", "R8", "R9"))
DATA = 0x10000
PATH = DATA + 0x40
BUFFER = DATA + 0x100
MODULE = module_for(registers=REGISTERS)
CONTENT = b"flag{from_a_file}\n"


def _memory() -> ConcreteMemory:
    memory = ConcreteMemory(Endianness.LITTLE)
    memory.map(Mapping("data", DATA, 0x1000, True, True, None))
    memory.write(PATH, b"flag.txt\0")
    return memory


def _call(libc: ConcreteLibc, name: str, memory: ConcreteMemory, *arguments: int) -> int:
    registers = dict(zip(SYSV_X86_64.integer_parameters, arguments, strict=False))
    return libc(name, registers, memory)["RAX"]


def test_the_interpreter_reads_the_file_it_is_given() -> None:
    memory = _memory()
    libc = ConcreteLibc(SYSV_X86_64, ConcreteIO(files={"flag.txt": CONTENT}))
    handle = _call(libc, "fopen", memory, PATH, 0)
    assert handle == FILE_HANDLES
    assert _call(libc, "feof", memory, handle) == 0
    assert _call(libc, "fgets", memory, BUFFER, 64, handle) == BUFFER
    assert memory.read_c_string(BUFFER) == CONTENT
    assert _call(libc, "feof", memory, handle) == 1
    assert _call(libc, "fclose", memory, handle) == 0


def test_an_unopened_stream_is_not_guessed_at() -> None:
    libc = ConcreteLibc(SYSV_X86_64, ConcreteIO())
    try:
        _call(libc, "fgets", _memory(), BUFFER, 64, 0x1234)
    except UnsupportedLibraryCallError as error:
        assert "not opened" in str(error)
    else:
        raise AssertionError("reading an unknown stream should not be modeled")


def _symbolic_state(content: tuple[sx.Expr, ...]) -> State:
    memory = SymbolicMemory(_memory())
    return State(id=1, frames=[], memory=memory, io=SymbolicIO(contents={"flag.txt": content}))


def test_the_solver_reads_the_same_bytes_the_interpreter_would() -> None:
    executor = Executor(MODULE, Z3Backend(), Goal())
    symbols = tuple(sx.symbol(f"file_flag_txt_{index:04}", 8) for index in range(len(CONTENT)))
    state = _symbolic_state(symbols)
    libc = SymbolicLibc(SYSV_X86_64)

    def call(name: str, *arguments: int) -> Returned:
        outcomes = libc.call(
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
        return outcome

    assignment = {symbol.name: byte for symbol, byte in zip(symbols, CONTENT, strict=True)}
    handle = evaluate(call("fopen", PATH, 0).outputs["RAX"], assignment)
    assert handle == FILE_HANDLES
    call("fgets", BUFFER, 64, handle)
    read = bytes(
        evaluate(state.memory.read_byte(BUFFER + index), assignment)
        for index in range(len(CONTENT))
    )
    assert read == CONTENT
    assert evaluate(call("feof", handle).outputs["RAX"], assignment) == 1


def _open(state: State, path: int) -> Returned | Failed:
    outcomes = SymbolicLibc(SYSV_X86_64).call(
        Executor(MODULE, Z3Backend(), Goal()),
        state,
        "fopen",
        {SYSV_X86_64.integer_parameters[0]: sx.const(path, 64)},
        Origin(0, 0),
    )
    assert outcomes is not None
    (outcome,) = outcomes
    assert isinstance(outcome, Returned | Failed)
    return outcome


def test_a_path_no_input_was_planned_for_becomes_one() -> None:
    """The analysis reads the paths it can see; one it only meets here is an input too."""
    state = _symbolic_state(())
    state.io.contents.clear()
    assert isinstance(_open(state, PATH), Returned)
    content = state.io.contents["flag.txt"]
    assert content and not any(symbol.is_const for symbol in content)


def test_a_path_the_program_computes_is_refused() -> None:
    state = _symbolic_state(())
    state.memory.write_byte(PATH, sx.symbol("chosen", 8))
    outcome = _open(state, PATH)
    assert isinstance(outcome, Failed)
    assert "a path the program computes" in outcome.detail


def test_stdin_still_reads_from_stdin() -> None:
    memory = _memory()
    libc = ConcreteLibc(SYSV_X86_64, ConcreteIO(stdin=b"typed\n"))
    assert _call(libc, "fgets", memory, BUFFER, 64, STANDARD_STREAMS["stdin"]) == BUFFER
    assert memory.read_c_string(BUFFER) == b"typed\n"


def test_seeking_measures_a_file_the_way_a_program_does() -> None:
    """`fseek(f, 0, SEEK_END)` then `ftell` is how a program asks how long a file is."""
    memory = _memory()
    libc = ConcreteLibc(SYSV_X86_64, ConcreteIO(files={"flag.txt": CONTENT}))
    handle = _call(libc, "fopen", memory, PATH, 0)
    assert _call(libc, "fseek", memory, handle, 0, 2) == 0
    assert _call(libc, "ftell", memory, handle) == len(CONTENT)
    assert _call(libc, "rewind", memory, handle) == 0
    assert _call(libc, "ftell", memory, handle) == 0
    assert _call(libc, "fread", memory, BUFFER, 1, len(CONTENT), handle) == len(CONTENT)
    assert memory.read(BUFFER, len(CONTENT)) == CONTENT

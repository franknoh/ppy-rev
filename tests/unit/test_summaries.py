"""The symbolic C library models agree with the concrete ones, byte for byte."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ppy_rev.abi import SYSV_X86_64
from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.execution.program import STANDARD_STREAMS
from ppy_rev.ir.model import Endianness, Origin
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.summaries.concrete import ConcreteIO, ConcreteLibc
from ppy_rev.summaries.symbolic import SymbolicLibc
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.evaluate import evaluate
from ppy_rev.symbolic.executor import Executor, Failed, Goal, Returned, StopReason
from ppy_rev.symbolic.memory import SymbolicMemory
from ppy_rev.symbolic.state import State, SymbolicIO
from support.revir import module_for

REGISTERS = tuple((name, 64) for name in ("RAX", "RCX", "RDX", "RSP", "RSI", "RDI", "R8", "R9"))
DATA = 0x10000
LEFT = DATA + 0x100
RIGHT = DATA + 0x200
OUT = DATA + 0x300
MODULE = module_for(registers=REGISTERS)

text = st.binary(min_size=0, max_size=12)


def _image() -> ConcreteMemory:
    memory = ConcreteMemory(Endianness.LITTLE)
    memory.map(Mapping("data", DATA, 0x1000, True, True, None))
    return memory


def _run_both(
    name: str,
    arguments: list[int],
    left: bytes,
    right: bytes,
    stdin: bytes = b"",
    concrete_right: bool = False,
) -> None:
    """Place `left`/`right` at LEFT/RIGHT (symbolically, then concretely) and compare."""
    concrete_memory = _image()
    concrete_memory.write(LEFT, left + b"\0")
    concrete_memory.write(RIGHT, right + b"\0")
    registers = dict(zip(SYSV_X86_64.integer_parameters, arguments, strict=False))
    io = ConcreteIO(stdin=stdin)
    concrete = ConcreteLibc(SYSV_X86_64, io)(name, dict(registers), concrete_memory)

    executor = Executor(MODULE, Z3Backend(), Goal())
    image = _image()
    symbolic = [(LEFT, left)]
    if concrete_right:
        image.write(RIGHT, right + b"\0")
    else:
        symbolic.append((RIGHT, right))
    memory = SymbolicMemory(image)
    assignment: dict[str, int] = {}
    for base, content in symbolic:
        for offset, byte in enumerate(content):
            symbol = sx.symbol(f"b{base:x}_{offset}", 8)
            memory.write_byte(base + offset, symbol)
            assignment[symbol.name] = byte
    stdin_symbols = tuple(sx.symbol(f"in_{index}", 8) for index in range(len(stdin)))
    assignment.update(
        {symbol.name: byte for symbol, byte in zip(stdin_symbols, stdin, strict=True)}
    )
    state = State(id=1, frames=[], memory=memory, io=SymbolicIO(stdin=stdin_symbols))
    symbolic_arguments = {register: sx.const(value, 64) for register, value in registers.items()}
    outcomes = SymbolicLibc(SYSV_X86_64).call(
        executor, state, name, symbolic_arguments, Origin(0, 0)
    )
    assert outcomes is not None
    (outcome,) = outcomes
    assert isinstance(outcome, Returned), outcome
    result = evaluate(outcome.outputs["RAX"], assignment)
    assert result == concrete["RAX"], (name, left, right, result, concrete["RAX"])
    for address in range(DATA, DATA + 0x400):
        symbolic_byte = evaluate(memory.read_byte(address), assignment)
        assert symbolic_byte == concrete_memory.read(address, 1)[0], (name, hex(address))


@settings(max_examples=60, deadline=None)
@given(text)
def test_strlen(value: bytes) -> None:
    _run_both("strlen", [LEFT], value, b"")


@settings(max_examples=80, deadline=None)
@given(text, text)
def test_strcmp_and_strncmp(left: bytes, right: bytes) -> None:
    _run_both("strcmp", [LEFT, RIGHT], left, right)
    for limit in (0, 1, 3, 20):
        _run_both("strncmp", [LEFT, RIGHT, limit], left, right)


@settings(max_examples=60, deadline=None)
@given(text, text, st.integers(0, 13))
def test_memcmp_memcpy_memset(left: bytes, right: bytes, size: int) -> None:
    _run_both("memcmp", [LEFT, RIGHT, size], left, right)
    _run_both("memcpy", [OUT, LEFT, size], left, right)
    _run_both("memset", [OUT, 0x1FF, size], left, right)


@settings(max_examples=60, deadline=None)
@given(text, text)
def test_strcpy_and_strcspn(left: bytes, right: bytes) -> None:
    _run_both("strcpy", [OUT, LEFT], left, right)
    # The model scans a symbolic string against a concrete set of rejected bytes.
    rejected = bytes(sorted(set(right) - {0}))[:4]
    _run_both("strcspn", [LEFT, RIGHT], left, rejected, concrete_right=True)


@settings(max_examples=60, deadline=None)
@given(st.binary(min_size=1, max_size=20), st.integers(1, 24))
def test_read_and_fgets(stdin: bytes, size: int) -> None:
    _run_both("read", [0, OUT, size], b"", b"", stdin)
    _run_both("fgets", [OUT, size, STANDARD_STREAMS["stdin"]], b"", b"", stdin)


def test_strcspn_refuses_a_symbolic_rejected_set() -> None:
    memory = SymbolicMemory(_image())
    memory.write_byte(RIGHT, sx.symbol("reject", 8))
    state = State(id=1, frames=[], memory=memory, io=SymbolicIO(stdin=()))
    arguments = {"RDI": sx.const(LEFT, 64), "RSI": sx.const(RIGHT, 64)}
    executor = Executor(MODULE, Z3Backend(), Goal())
    outcomes = SymbolicLibc(SYSV_X86_64).call(executor, state, "strcspn", arguments, Origin(0, 0))
    assert outcomes is not None
    (outcome,) = outcomes
    assert isinstance(outcome, Failed) and outcome.reason is StopReason.UNSUPPORTED

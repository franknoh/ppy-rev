"""The symbolic C library models agree with the concrete ones, byte for byte."""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from ppy_rev.abi import SYSV_X86_64
from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.execution.program import STANDARD_STREAMS
from ppy_rev.ir.model import Endianness, Origin
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.summaries.concrete import ConcreteIO, ConcreteLibc, UnsupportedLibraryCallError
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
numbers = st.lists(st.sampled_from(b" \t+-0123456789a"), max_size=12).map(bytes)
scan_input = (
    st.lists(st.sampled_from(b" \n+-0123456789ax,\xff"), max_size=10)
    .map(bytes)
    # Runs of whitespace a directive skips are explored as one byte (see the model).
    .map(lambda data: re.sub(rb"[ \n]+", lambda run: run.group(0)[:1], data))
)


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
    concrete_left: bool = False,
) -> None:
    """Place `left`/`right` at LEFT/RIGHT (symbolically, then concretely) and compare.

    A model may split into several states; exactly one of them must admit the concrete
    input, and it must agree with the concrete model.
    """
    concrete_memory = _image()
    concrete_memory.write(LEFT, left + b"\0")
    concrete_memory.write(RIGHT, right + b"\0")
    registers = dict(zip(SYSV_X86_64.integer_parameters, arguments, strict=False))
    io = ConcreteIO(stdin=stdin)
    concrete = ConcreteLibc(SYSV_X86_64, io)(name, dict(registers), concrete_memory)

    executor = Executor(MODULE, Z3Backend(), Goal())
    image = _image()
    symbolic: list[tuple[int, bytes]] = []
    for base, content, concrete_content in (
        (LEFT, left, concrete_left),
        (RIGHT, right, concrete_right),
    ):
        if concrete_content:
            image.write(base, content + b"\0")
        else:
            symbolic.append((base, content))
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
    (outcome,) = [
        outcome
        for outcome in outcomes
        if all(evaluate(item.condition, assignment) for item in outcome.state.constraints)
    ]
    assert isinstance(outcome, Returned), outcome
    result = evaluate(outcome.outputs["RAX"], assignment)
    assert result == concrete["RAX"], (name, left, right, stdin, result, concrete["RAX"])
    assert outcome.state.io.stdin_position == io.stdin_position or name in ("fgets", "gets")
    for address in range(DATA, DATA + 0x400):
        symbolic_byte = evaluate(outcome.state.memory.read_byte(address), assignment)
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
def test_string_copies_and_strcspn(left: bytes, right: bytes) -> None:
    _run_both("strcpy", [OUT, LEFT], left, right)
    for size in (0, 1, 5, 24):
        _run_both("strncpy", [OUT, LEFT, size], left, right)
    # The model scans a symbolic string against a concrete set of rejected bytes.
    rejected = bytes(sorted(set(right) - {0}))[:4]
    _run_both("strcspn", [LEFT, RIGHT], left, rejected, concrete_right=True)


@settings(max_examples=60, deadline=None)
@given(st.binary(min_size=1, max_size=20), st.integers(1, 24))
def test_output_setup_functions_do_nothing(stdin: bytes, size: int) -> None:
    _run_both("setbuf", [STANDARD_STREAMS["stdout"], 0], b"", b"", stdin)
    _run_both("setvbuf", [STANDARD_STREAMS["stdout"], 0, 2, size], b"", b"", stdin)


@settings(max_examples=60, deadline=None)
@given(st.binary(min_size=1, max_size=20), st.integers(1, 24))
def test_read_and_fgets(stdin: bytes, size: int) -> None:
    _run_both("read", [0, OUT, size], b"", b"", stdin)
    _run_both("fgets", [OUT, size, STANDARD_STREAMS["stdin"]], b"", b"", stdin)
    _run_both("gets", [OUT], b"", b"", stdin)


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


@settings(max_examples=80, deadline=None)
@given(numbers)
def test_number_parsing(value: bytes) -> None:
    _run_both("atoi", [LEFT], value, b"")
    _run_both("atol", [LEFT], value, b"")
    _run_both("strtol", [LEFT, OUT, 10], value, b"")


@settings(max_examples=120, deadline=None)
@given(
    st.sampled_from([b"%s", b"%3s", b"%d", b"%d %d", b"%c", b"x%d", b"%hhd", b"%*d %s", b"%d,%d"]),
    scan_input,
)
def test_scanf(template: bytes, data: bytes) -> None:
    pointers = [LEFT, OUT, OUT + 0x40, OUT + 0x80]
    _run_both("scanf", pointers, template, b"", stdin=data, concrete_left=True)


@settings(max_examples=60, deadline=None)
@given(
    st.sampled_from([b"%d", b"%ld", b"%hhd"]),
    st.sampled_from([b"", b"+", b"-"]),
    st.sampled_from(
        [
            b"9223372036854775807",
            b"9223372036854775808",
            b"18446744073709551615",
            b"18446744073709551616",
            b"184467440737095516150",
            b"000000000000000000000042",
            b"99999999999999999999999",
            b"4294967295",
            b"1844674407370955161",
        ]
    ),
    st.sampled_from([b"", b" ", b"x"]),
)
def test_scanf_long_numbers(template: bytes, sign: bytes, digits: bytes, tail: bytes) -> None:
    """Numbers past 18 digits saturate like strtol; the value then keeps its low bytes."""
    _run_both("scanf", [OUT], template, b"", stdin=sign + digits + tail, concrete_left=True)


def test_character_functions() -> None:
    character = sx.symbol("c", 64)
    concrete = ConcreteLibc(SYSV_X86_64)
    for name in ("isalpha", "isdigit", "isspace", "ispunct", "toupper", "tolower"):
        executor = Executor(MODULE, Z3Backend(), Goal())
        state = State(id=1, frames=[], memory=SymbolicMemory(_image()), io=SymbolicIO())
        outcomes = SymbolicLibc(SYSV_X86_64).call(
            executor, state, name, {"RDI": character}, Origin(0, 0)
        )
        assert outcomes is not None
        (outcome,) = outcomes
        assert isinstance(outcome, Returned)
        for value in [*range(-140, 270), 0x7FFFFFFF, -0x80000000, 0x1_0000_0041]:
            assignment = {"c": value & 0xFFFFFFFFFFFFFFFF}
            admitted = all(
                evaluate(item.condition, assignment) for item in outcome.state.constraints
            )
            try:
                expected = concrete(name, dict(assignment, RDI=assignment["c"]), _image())
            except UnsupportedLibraryCallError:
                assert not admitted, (name, value)
                continue
            assert admitted, (name, value)
            assert evaluate(outcome.outputs["RAX"], assignment) == expected["RAX"], (name, value)


def test_input_after_a_symbolic_length_line_is_a_hiding_approximation() -> None:
    executor = Executor(MODULE, Z3Backend(), Goal())
    stdin = tuple(sx.symbol(f"in_{index}", 8) for index in range(8))
    state = State(id=1, frames=[], memory=SymbolicMemory(_image()), io=SymbolicIO(stdin=stdin))
    arguments = {
        "RDI": sx.const(OUT, 64),
        "RSI": sx.const(4, 64),
        "RDX": sx.const(STANDARD_STREAMS["stdin"], 64),
    }
    outcomes = SymbolicLibc(SYSV_X86_64).call(executor, state, "fgets", arguments, Origin(0, 0))
    assert outcomes is not None
    assert state.io.stdin == ()
    assert executor.statistics.hiding_approximations == {
        "stdin after a symbolic-length fgets line is treated as empty"
    }


def test_scanning_unconstrained_input_needs_no_solver() -> None:
    """Input shapes are tests on single bytes: feasibility follows without asking Z3."""
    image = _image()
    image.write(LEFT, b"%d\0")
    memory = SymbolicMemory(image)
    stdin = tuple(sx.symbol(f"in_{index}", 8) for index in range(8))
    state = State(id=1, frames=[], memory=memory, io=SymbolicIO(stdin=stdin))
    executor = Executor(MODULE, Z3Backend(), Goal())
    arguments = {"RDI": sx.const(LEFT, 64), "RSI": sx.const(OUT, 64)}
    outcomes = SymbolicLibc(SYSV_X86_64).call(executor, state, "scanf", arguments, Origin(0, 0))
    assert outcomes is not None
    # One state per way the number can end, and every one of them is reachable.
    assert len(outcomes) > 8
    assert executor.statistics.solver_calls == 0


def test_rand_follows_the_seed_in_both_models() -> None:
    concrete = ConcreteLibc(SYSV_X86_64)
    memory = _image()
    concrete("srand", {"RDI": 1234}, memory)
    expected = [concrete("rand", {}, memory)["RAX"] for _ in range(5)]
    executor = Executor(MODULE, Z3Backend(), Goal())
    state = State(id=1, frames=[], memory=SymbolicMemory(_image()), io=SymbolicIO())
    libc = SymbolicLibc(SYSV_X86_64)
    (seeded,) = libc.call(executor, state, "srand", {"RDI": sx.const(1234, 64)}, Origin(0, 0)) or []
    assert isinstance(seeded, Returned)
    values: list[int] = []
    for _ in range(5):
        (outcome,) = libc.call(executor, state, "rand", {}, Origin(0, 0)) or []
        assert isinstance(outcome, Returned)
        values.append(outcome.outputs["RAX"].value)
    assert values == expected
    symbolic_seed = {"RDI": sx.symbol("seed", 64)}
    (refused,) = libc.call(executor, state, "srand", symbolic_seed, Origin(0, 0)) or []
    assert isinstance(refused, Failed) and refused.reason is StopReason.UNSUPPORTED

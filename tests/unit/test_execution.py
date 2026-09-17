from __future__ import annotations

import pytest

from ppy_rev.execution.interpreter import ExecutionError, FaultKind, Interpreter, Limits
from ppy_rev.execution.memory import ConcreteMemory, Mapping, MemoryFaultError
from ppy_rev.execution.process import RETURN_SENTINEL, enter_call, standard_memory
from ppy_rev.ghidra.schema import PcodeOp
from ppy_rev.ir.model import Endianness, Module
from ppy_rev.lift.lifter import lift_export
from support.exports import ProgramBuilder, call, const, op, ram, reg, ret


def _run(
    program: ProgramBuilder, name: str, registers: dict[str, int], limits: Limits | None = None
) -> dict[str, int]:
    module = lift_export(program.build()).module
    return _call(module, name, registers, limits)


def _call(
    module: Module, name: str, registers: dict[str, int], limits: Limits | None = None
) -> dict[str, int]:
    function = module.function_named(name)
    assert function is not None
    memory = standard_memory(module)
    frame = enter_call(module, memory, registers)
    return Interpreter(module, memory, limits=limits).call(
        function, frame.registers, frame.return_address
    )


def test_memory_permissions_and_endianness() -> None:
    memory = ConcreteMemory(Endianness.LITTLE)
    memory.map(Mapping("ro", 0x1000, 0x10, True, False, b"\x01\x02\x03\x04"))
    memory.map(Mapping("rw", 0x2000, 0x10, True, True, None))
    assert memory.load(0x1000, 32) == 0x04030201
    assert memory.load(0x1004, 16) == 0
    memory.store(0x2000, 0xAABBCCDD, 32)
    assert memory.read(0x2000, 4) == b"\xdd\xcc\xbb\xaa"
    with pytest.raises(MemoryFaultError):
        memory.store(0x1000, 1, 8)
    with pytest.raises(MemoryFaultError):
        memory.load(0x100E, 32)
    with pytest.raises(MemoryFaultError):
        memory.load(0x3000, 8)
    with pytest.raises(ValueError, match="overlaps"):
        memory.map(Mapping("clash", 0x2008, 0x10, True, True, None))


def _loop_program() -> ProgramBuilder:
    program = ProgramBuilder()
    loop = program.code(0x1000, [op("COPY", [const(0, 8)], reg("RCX"))])
    exit_ = program.code(
        loop,
        [
            op("INT_ADD", [reg("RCX"), reg("RDI")], reg("RCX")),
            op("INT_SUB", [reg("RSI"), const(1, 8)], reg("RSI")),
            op("INT_NOTEQUAL", [reg("RSI"), const(0, 8)], reg("ZF")),
            op("CBRANCH", [ram(loop), reg("ZF")]),
        ],
    )
    after = program.code(exit_, [op("COPY", [reg("RCX")], reg("RAX"))])
    program.code(after, ret(), length=1)
    program.function("multiply", 0x1000)
    return program


def test_loop_with_phis_computes_the_expected_value() -> None:
    outputs = _run(_loop_program(), "multiply", {"RDI": 7, "RSI": 6})
    assert outputs["RAX"] == 42


def test_step_limit_stops_runaway_loops() -> None:
    with pytest.raises(ExecutionError) as error:
        _run(_loop_program(), "multiply", {"RDI": 1, "RSI": 0}, Limits(max_steps=1000))
    assert error.value.kind is FaultKind.STEP_LIMIT


def test_internal_call_checks_the_pushed_return_address() -> None:
    program = ProgramBuilder()
    program.code(0x2000, [op("INT_MULT", [reg("RDI"), reg("RDI")], reg("RAX")), *ret()])
    program.function("square", 0x2000)
    after = program.code(0x1000, call(0x2000, 0x1004))
    program.code(after, ret(), length=1)
    program.function("caller", 0x1000)
    assert _run(program, "caller", {"RDI": 9})["RAX"] == 81

    corrupt = ProgramBuilder()
    corrupt.code(
        0x2000,
        [op("STORE", [reg("RSP"), const(0x4141, 8)]), *ret()],
    )
    corrupt.function("smash", 0x2000)
    after = corrupt.code(0x1000, call(0x2000, 0x1004))
    corrupt.code(after, ret(), length=1)
    corrupt.function("caller", 0x1000)
    with pytest.raises(ExecutionError) as error:
        _run(corrupt, "caller", {})
    assert error.value.kind is FaultKind.RETURN_ADDRESS_MISMATCH


def test_outermost_return_reaches_the_sentinel() -> None:
    program = ProgramBuilder()
    program.code(0x1000, ret(), length=1)
    program.function("f", 0x1000)
    outputs = _run(program, "f", {})
    assert outputs["RIP"] == RETURN_SENTINEL


@pytest.mark.parametrize(
    ("pcode", "kind"),
    [
        ([op("INT_DIV", [reg("RDI"), reg("RSI")], reg("RAX"))], FaultKind.DIVISION_BY_ZERO),
        ([op("LOAD", [const(0x10, 8)], reg("RAX"))], FaultKind.MEMORY_FAULT),
        ([op("FLOAT_ADD", [reg("RDI"), reg("RSI")], reg("RAX"))], FaultKind.UNSUPPORTED),
        ([op("CALLOTHER", [const(0, 4)], None, user_op="syscall")], FaultKind.UNSUPPORTED),
        ([op("BRANCHIND", [reg("RDI")])], FaultKind.UNRESOLVED_INDIRECT_JUMP),
        (call(0x9000, 0x1004), FaultKind.UNKNOWN_CALL_TARGET),
    ],
)
def test_unmodeled_behaviour_is_an_error(pcode: list[PcodeOp], kind: FaultKind) -> None:
    program = ProgramBuilder()
    after = program.code(0x1000, pcode)
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    with pytest.raises(ExecutionError) as error:
        _run(program, "f", {"RDI": 0x1234, "RSI": 0})
    assert error.value.kind is kind
    assert error.value.location.function == "f"


def test_instruction_observer_sees_every_instruction() -> None:
    module = lift_export(_loop_program().build()).module
    function = module.function_named("multiply")
    assert function is not None
    memory = standard_memory(module)
    frame = enter_call(module, memory, {"RDI": 1, "RSI": 2})
    seen: list[int] = []
    Interpreter(module, memory, observer=seen.append).call(
        function, frame.registers, frame.return_address
    )
    assert seen == [0x1000, 0x1004, 0x1004, 0x1008, 0x100C]

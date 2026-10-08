from __future__ import annotations

from ppy_rev.diagnostics import DiagnosticCode, Severity
from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Branch,
    Call,
    Const,
    DirectTarget,
    ExternalTarget,
    Function,
    Halt,
    IndirectJump,
    Jump,
    Module,
    Piece,
    Return,
    Stop,
    Subpiece,
    TailCall,
    UnaryOp,
    UnaryOpcode,
    Unsupported,
    UserOp,
    Var,
    operation_inputs,
    operation_output,
)
from ppy_rev.ir.validate import validate_module
from ppy_rev.lift.lifter import LiftResult, lift_export
from support.exports import ProgramBuilder, call, const, op, ram, reg, ret, tmp


def _lift(program: ProgramBuilder) -> LiftResult:
    result = lift_export(program.build())
    assert validate_module(result.module) == []
    return result


def _function(module: Module, name: str) -> Function:
    function = module.function_named(name)
    assert function is not None
    return function


def _returned(module: Module, function: Function, register: str, block: int = -1) -> object:
    terminator = function.blocks[block].terminator
    assert isinstance(terminator, Return)
    return terminator.values[function.output_registers.index(register)]


def _input(function: Function, register: str) -> Var:
    return next(item.value for item in function.inputs if item.register == register)


def test_straight_line_add_returns_through_register_state() -> None:
    program = ProgramBuilder()
    after = program.code(0x1000, [op("INT_ADD", [reg("RAX"), const(1, 8)], reg("RAX"))])
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    module = _lift(program).module
    function = _function(module, "f")
    (block,) = function.blocks
    add = block.operations[0]
    assert isinstance(add, BinaryOp)
    assert add.opcode is BinaryOpcode.ADD
    assert add.left == _input(function, "RAX")
    assert add.right == Const(1, 64)
    assert _returned(module, function, "RAX") == add.output
    assert add.origin.address == 0x1000
    assert isinstance(block.terminator, Return)
    assert block.terminator.return_address is not None


def test_partial_register_write_composes_the_whole_register() -> None:
    program = ProgramBuilder()
    after = program.code(0x1000, [op("COPY", [const(5, 1)], reg("AH"))])
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    module = _lift(program).module
    function = _function(module, "f")
    operations = function.blocks[0].operations
    truncate, low_join, high, whole = operations[:4]
    rax = _input(function, "RAX")
    assert isinstance(truncate, UnaryOp) and truncate.opcode is UnaryOpcode.TRUNCATE
    assert truncate.operand == rax and truncate.output.width == 8
    assert isinstance(low_join, Piece) and low_join.high == Const(5, 8)
    assert isinstance(high, Subpiece) and high.low_bit == 16 and high.output.width == 48
    assert isinstance(whole, Piece) and whole.output.width == 64
    assert _returned(module, function, "RAX") == whole.output


def test_partial_register_read_is_a_subpiece() -> None:
    program = ProgramBuilder()
    after = program.code(0x1000, [op("INT_ZEXT", [reg("AH")], reg("RCX"))])
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    function = _function(_lift(program).module, "f")
    subpiece, extend = function.blocks[0].operations[:2]
    assert isinstance(subpiece, Subpiece) and subpiece.low_bit == 8
    assert subpiece.operand == _input(function, "RAX")
    assert isinstance(extend, UnaryOp) and extend.operand == subpiece.output


def test_loop_counter_becomes_a_phi() -> None:
    program = ProgramBuilder()
    loop = program.code(0x1000, [op("COPY", [const(0, 8)], reg("RCX"))])
    exit_ = program.code(
        loop,
        [
            op("INT_ADD", [reg("RCX"), const(1, 8)], reg("RCX")),
            op("INT_LESS", [reg("RCX"), const(10, 8)], reg("CF")),
            op("CBRANCH", [ram(loop), reg("CF")]),
        ],
    )
    program.code(exit_, ret(), length=1)
    program.function("f", 0x1000)
    module = _lift(program).module
    function = _function(module, "f")
    header = function.blocks[1]
    assert header.address == loop
    (phi,) = [phi for phi in header.phis if phi.output.width == 64]
    add = header.operations[0]
    assert isinstance(add, BinaryOp)
    assert dict(phi.incoming) == {0: Const(0, 64), 1: add.output}
    assert add.left == phi.output
    branch = header.terminator
    assert isinstance(branch, Branch) and (branch.true_target, branch.false_target) == (1, 2)
    assert "RCX" not in {item.register for item in function.inputs}


def test_branch_to_entry_gets_a_preheader() -> None:
    program = ProgramBuilder()
    program.code(
        0x1000,
        [
            op("INT_SUB", [reg("RAX"), const(1, 8)], reg("RAX")),
            op("INT_NOTEQUAL", [reg("RAX"), const(0, 8)], reg("ZF")),
            op("CBRANCH", [ram(0x1000), reg("ZF")]),
        ],
    )
    program.code(0x1004, ret(), length=1)
    program.function("f", 0x1000)
    function = _function(_lift(program).module, "f")
    preheader = function.blocks[0]
    assert preheader.operations == () and isinstance(preheader.terminator, Jump)
    assert preheader.terminator.target == 1
    assert {predecessor for predecessor, _ in function.blocks[1].phis[0].incoming} == {0, 1}


def test_pcode_relative_branch_splits_an_instruction() -> None:
    program = ProgramBuilder()
    after = program.code(
        0x1000,
        [
            op("INT_EQUAL", [reg("RCX"), const(0, 8)], tmp(0x100, 1)),
            op("CBRANCH", [const(2, 8), tmp(0x100, 1)]),
            op("INT_ADD", [reg("RAX"), const(1, 8)], reg("RAX")),
            op("COPY", [reg("RAX")], reg("RDX")),
        ],
    )
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    function = _function(_lift(program).module, "f")
    starts = [(block.address, len(block.operations)) for block in function.blocks]
    assert len(function.blocks) == 3
    assert starts[0][0] == starts[1][0] == starts[2][0] == 0x1000
    branch = function.blocks[0].terminator
    assert isinstance(branch, Branch)
    assert branch.true_target == 2 and branch.false_target == 1


def test_calls_resolve_internal_imported_and_noreturn_targets() -> None:
    program = ProgramBuilder()
    program.import_("puts", 0x3000)
    program.import_("exit", 0x3010, no_return=True)
    program.code(0x2000, ret(), length=1)
    program.function("helper", 0x2000)
    after = program.code(0x1000, call(0x2000, 0x1004))
    after = program.code(after, call(0x3000, 0x1008))
    program.code(after, call(0x3010, 0x100C))
    program.function("main", 0x1000)
    module = _lift(program).module
    main = _function(module, "main")
    calls = [operation for block in main.blocks for operation in block.operations]
    targets = [operation.target for operation in calls if isinstance(operation, Call)]
    assert targets == [
        DirectTarget(0x2000),
        ExternalTarget("puts", 0x3000),
        ExternalTarget("exit", 0x3010),
    ]
    assert isinstance(main.blocks[-1].terminator, Halt)
    assert [external.name for external in module.externals] == ["exit", "puts"]
    assert module.externals[0].addresses == (0x3010,)


def test_jump_to_another_function_is_a_tail_call() -> None:
    program = ProgramBuilder()
    program.code(0x2000, ret(), length=1)
    program.function("helper", 0x2000)
    program.code(0x1000, [op("BRANCH", [ram(0x2000)])])
    program.function("f", 0x1000)
    function = _function(_lift(program).module, "f")
    terminator = function.blocks[0].terminator
    assert isinstance(terminator, TailCall)
    assert terminator.call.target == DirectTarget(0x2000)
    assert terminator.values == terminator.call.results


def test_indirect_jump_uses_recovered_targets() -> None:
    program = ProgramBuilder()
    program.code(0x1000, [op("BRANCHIND", [reg("RAX")])])
    program.indirect_flows(0x1000, (0x1010, 0x1020))
    program.code(0x1010, ret(), length=1)
    program.code(0x1020, ret(), length=1)
    program.function("f", 0x1000)
    function = _function(_lift(program).module, "f")
    terminator = function.blocks[0].terminator
    assert isinstance(terminator, IndirectJump)
    assert [address for address, _ in terminator.targets] == [0x1010, 0x1020]


def test_missing_instruction_stops_with_a_diagnostic() -> None:
    program = ProgramBuilder()
    program.code(0x1000, [op("BRANCH", [ram(0x5000)])])
    program.function("f", 0x1000)
    result = _lift(program)
    function = _function(result.module, "f")
    assert isinstance(function.blocks[-1].terminator, Stop)
    assert [d.code for d in result.diagnostics] == [DiagnosticCode.MISSING_INSTRUCTION]


def test_unmodeled_operations_are_explicit() -> None:
    program = ProgramBuilder()
    after = program.code(
        0x1000,
        [
            # x87's 80-bit format has no model; binary32 and binary64 do.
            op("COPY", [const(0, 10)], tmp(0, 10)),
            op("COPY", [const(0, 10)], tmp(16, 10)),
            op("FLOAT_ADD", [tmp(0, 10), tmp(16, 10)], tmp(32, 10)),
            op("CALLOTHER", [const(5, 4), reg("RAX")], reg("RCX"), user_op="syscall"),
            op("LOAD", [reg("RAX")], reg("RDX"), memory_space="register"),
        ],
    )
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    result = _lift(program)
    operations = _function(result.module, "f").blocks[0].operations
    unsupported = [item for item in operations if isinstance(item, Unsupported)]
    assert [item.pcode_opcode for item in unsupported] == ["FLOAT_ADD", "LOAD"]
    assert any(isinstance(item, UserOp) and item.name == "syscall" for item in operations)
    codes = [(d.code, d.severity) for d in result.diagnostics]
    assert codes == [
        (DiagnosticCode.UNSUPPORTED_FLOAT_OPERATION, Severity.ERROR),
        (DiagnosticCode.UNSUPPORTED_USER_OP, Severity.WARNING),
        (DiagnosticCode.UNSUPPORTED_ADDRESS_SPACE, Severity.ERROR),
    ]


def test_temporaries_stay_instruction_local() -> None:
    program = ProgramBuilder()
    after = program.code(
        0x1000,
        [
            op("INT_ADD", [reg("RAX"), const(2, 8)], tmp(0x80, 8)),
            op("INT_MULT", [tmp(0x80, 8), tmp(0x80, 8)], reg("RAX")),
        ],
    )
    after = program.code(after, [op("SUBPIECE", [reg("RAX"), const(0, 4)], tmp(0x80, 4))])
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    result = _lift(program)
    assert result.diagnostics == ()
    function = _function(result.module, "f")
    assert [item.register for item in function.inputs] == ["RAX", "RSP"]


def test_temporary_slices_read_the_wider_temporary() -> None:
    # Shape of x86 PCMPEQB: one 16-byte temporary, then comparisons of its single bytes.
    program = ProgramBuilder()
    after = program.code(
        0x1000,
        [
            op("COPY", [reg("RCX")], tmp(0x100, 8)),
            op("INT_EQUAL", [reg("AL"), tmp(0x100, 1)], tmp(0x200, 1)),
            op("INT_ZEXT", [tmp(0x103, 2)], reg("RDX")),
            op("INT_ZEXT", [tmp(0x200, 1)], reg("RAX")),
        ],
    )
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    result = _lift(program)
    assert result.diagnostics == ()
    function = _function(result.module, "f")
    rcx = _input(function, "RCX")
    operations = function.blocks[0].operations
    low = next(item for item in operations if isinstance(item, UnaryOp) and item.operand == rcx)
    assert low.opcode is UnaryOpcode.TRUNCATE and low.output.width == 8
    (middle,) = (item for item in operations if isinstance(item, Subpiece))
    assert (middle.operand, middle.low_bit, middle.output.width) == (rcx, 24, 16)
    assert [item.register for item in function.inputs] == ["RAX", "RCX", "RSP"]


def test_partial_temporary_writes_are_refused() -> None:
    program = ProgramBuilder()
    after = program.code(
        0x1000,
        [
            op("COPY", [reg("RCX")], tmp(0x100, 8)),
            op("COPY", [const(7, 1)], tmp(0x101, 1)),
            op("COPY", [tmp(0x100, 8)], reg("RAX")),
        ],
    )
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    result = _lift(program)
    operations = _function(result.module, "f").blocks[0].operations
    assert [item.pcode_opcode for item in operations if isinstance(item, Unsupported)] == [
        "VARNODE",
        "VARNODE",
        "VARNODE",
    ]
    assert {d.code for d in result.diagnostics} == {DiagnosticCode.UNSUPPORTED_OPERATION}


def test_undefined_temporaries_are_refused_not_inputs() -> None:
    program = ProgramBuilder()
    after = program.code(0x1000, [op("COPY", [const(1, 8)], reg("RCX"))])
    after = program.code(after, [op("INT_ADD", [tmp(0x80, 8), reg("RCX")], reg("RAX"))])
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    result = _lift(program)
    function = _function(result.module, "f")
    assert [item.register for item in function.inputs] == ["RSP"]
    (block,) = function.blocks
    undefined = block.operations[0]
    assert isinstance(undefined, Unsupported) and undefined.output is not None
    add = next(item for item in block.operations if isinstance(item, BinaryOp))
    assert add.left == undefined.output
    assert [start.position for start in block.instructions] == [0, 0, 2]
    assert [d.code for d in result.diagnostics] == [DiagnosticCode.MALFORMED_PCODE]


def test_lifting_is_deterministic() -> None:
    from ppy_rev.ir.text import format_module

    def build() -> str:
        program = ProgramBuilder()
        loop = program.code(0x1000, [op("COPY", [const(0, 8)], reg("RCX"))])
        exit_ = program.code(
            loop,
            [
                op("INT_ADD", [reg("RCX"), reg("RAX")], reg("RCX")),
                op("INT_LESS", [reg("RCX"), const(10, 8)], reg("CF")),
                op("CBRANCH", [ram(loop), reg("CF")]),
            ],
        )
        program.code(exit_, ret(), length=1)
        program.function("f", 0x1000)
        return format_module(lift_export(program.build()).module)

    assert build() == build()


def test_a_loop_back_to_the_entry_reads_the_register_the_caller_left() -> None:
    """A function entered inside its own loop, reading a register nothing writes.

    The code before the entry falls into it, so the entry block has a predecessor and no
    value comes from outside. Nothing defines RAX on that path either, so the value is
    the one the caller left, and it is a function input. Building this used to raise.
    """
    program = ProgramBuilder()
    program.code(0x1000, [op("STORE", [reg("RSP"), reg("RAX")])])  # falls into the entry
    entry = program.code(
        0x1004,
        [
            op("INT_EQUAL", [reg("RDI"), const(0, 8)], reg("ZF")),
            op("CBRANCH", [ram(0x1000), reg("ZF")]),
        ],
    )
    program.code(entry, ret(), length=1)
    program.function("f", 0x1004)
    result = _lift(program)
    function = _function(result.module, "f")
    assert "RAX" in [item.register for item in function.inputs]
    assert result.diagnostics == ()
    # The entry gets a block of its own with nothing in it, so that the value carried
    # around the loop has somewhere to come from on the way in. Without it, the phi for
    # that value is replaced by a definition that reads it, and the simplifier walks
    # that definition for ever.
    entry, *rest = function.blocks
    assert entry.operations == () and entry.phis == ()
    assert isinstance(entry.terminator, Jump)
    assert all(block.id != 0 for block in rest)
    for block in function.blocks:
        for operation in block.operations:
            outputs = {output.id for output in operation_output(operation)}
            assert not outputs & {
                value.id for value in operation_inputs(operation) if isinstance(value, Var)
            }, operation


def test_deeply_nested_branches_lift() -> None:
    """SSA construction follows one predecessor edge per few frames.

    Python's default recursion limit runs out after a few hundred nested branches, which
    is well within what an unrolled checker reaches.
    """
    program = ProgramBuilder()
    address = 0x1000
    depth = 400
    for _ in range(depth):
        skip = address + 8
        program.code(
            address,
            [
                op("INT_ADD", [reg("RAX"), const(1, 8)], reg("RAX")),
                op("INT_EQUAL", [reg("RDI"), reg("RAX")], reg("ZF")),
                op("CBRANCH", [ram(skip), reg("ZF")]),
            ],
            length=4,
        )
        program.code(address + 4, [op("INT_ADD", [reg("RCX"), const(1, 8)], reg("RCX"))], length=4)
        address = skip
    program.code(address, ret(), length=1)
    program.function("f", 0x1000)
    function = _function(_lift(program).module, "f")
    assert len(function.blocks) > depth

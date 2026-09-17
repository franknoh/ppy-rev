from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from ppy_rev.execution.interpreter import ExecutionError, FaultKind, Interpreter
from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Branch,
    Const,
    Endianness,
    Function,
    Jump,
    Load,
    Module,
    Operand,
    Origin,
    Return,
    UnaryOp,
    UnaryOpcode,
)
from ppy_rev.ir.validate import validate_function, validate_module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.simplify.cfg import simplify_cfg
from ppy_rev.simplify.dce import eliminate_dead_code
from ppy_rev.simplify.fold import fold_function
from ppy_rev.simplify.interfaces import trim_interfaces
from ppy_rev.simplify.memory import forward_memory
from ppy_rev.simplify.pipeline import simplify_function, simplify_module
from support.exports import ProgramBuilder, call, const, op, reg, ret
from support.revir import FunctionBuilder, module_for

REGISTERS = (("A", 64), ("B", 64), ("R", 64))


def _single(build: FunctionBuilder, value: Operand) -> tuple[Module, Function]:
    block = build.blocks[0] if build.blocks else build.block()
    build.returns(block, value)
    function = build.finish(("R",))
    return module_for(function, registers=REGISTERS), function


def _returned(function: Function) -> Operand:
    terminator = function.blocks[-1].terminator
    assert isinstance(terminator, Return)
    return terminator.values[0]


def test_folding_respects_fixed_width_overflow() -> None:
    build = FunctionBuilder([("A", 64)])
    block = build.block()
    wrapped = block.binary(BinaryOpcode.ADD, Const(255, 8), Const(1, 8))
    extended = block.unary(UnaryOpcode.ZERO_EXTEND, wrapped, 64)
    _, function = _single(build, extended)
    assert _returned(eliminate_dead_code(fold_function(function))) == Const(0, 64)


def test_identities_and_constant_chains() -> None:
    build = FunctionBuilder([("A", 64), ("B", 64)])
    block = build.block()
    a = build.input("A")
    plus = block.binary(BinaryOpcode.ADD, a, Const(3, 64))
    minus = block.binary(BinaryOpcode.SUB, plus, Const(3, 64))
    xored = block.binary(BinaryOpcode.XOR, minus, minus)
    both = block.binary(BinaryOpcode.OR, xored, build.input("B"))
    _, function = _single(build, both)
    assert _returned(fold_function(function)) == build.input("B")


def test_truncate_of_extension_and_subpiece_of_piece() -> None:
    build = FunctionBuilder([("A", 64), ("B", 64)])
    block = build.block()
    low = block.unary(UnaryOpcode.TRUNCATE, build.input("A"), 16)
    wide = block.unary(UnaryOpcode.ZERO_EXTEND, low, 64)
    back = block.unary(UnaryOpcode.TRUNCATE, wide, 16)
    joined = block.piece(back, block.unary(UnaryOpcode.TRUNCATE, build.input("B"), 8))
    high = block.subpiece(joined, 8, 16)
    _, function = _single(build, block.unary(UnaryOpcode.ZERO_EXTEND, high, 64))
    folded = eliminate_dead_code(fold_function(function))
    extend = folded.blocks[0].operations[-1]
    assert isinstance(extend, UnaryOp) and extend.operand == low


def test_division_by_zero_constant_is_not_folded_away() -> None:
    build = FunctionBuilder([("A", 64)])
    block = build.block()
    block.binary(BinaryOpcode.UNSIGNED_DIV, Const(7, 64), Const(0, 64))
    _, function = _single(build, Const(1, 64))
    simplified = eliminate_dead_code(fold_function(function))
    assert any(isinstance(item, BinaryOp) for item in simplified.blocks[0].operations)


def test_store_to_load_forwarding_respects_aliasing() -> None:
    build = FunctionBuilder([("A", 64), ("B", 64)])
    block = build.block()
    base = build.input("A")
    slot = block.binary(BinaryOpcode.ADD, base, Const(8, 64))
    block.store(slot, Const(0x1234, 32))
    other = block.binary(BinaryOpcode.ADD, base, Const(12, 64))
    block.store(other, Const(0x55, 32))
    forwarded = block.load(slot, 32)
    block.store(build.input("B"), Const(0, 64))
    unknown = block.load(slot, 32)
    total = block.binary(BinaryOpcode.ADD, forwarded, unknown)
    _, function = _single(build, block.unary(UnaryOpcode.ZERO_EXTEND, total, 64))
    result = forward_memory(fold_function(function), Endianness.LITTLE, 64)
    loads = [item for item in result.blocks[0].operations if isinstance(item, Load)]
    assert loads == [next(item for item in result.blocks[0].operations if isinstance(item, Load))]
    add = next(
        item
        for item in result.blocks[0].operations
        if isinstance(item, BinaryOp) and item.output == total
    )
    assert add.left == Const(0x1234, 32)
    assert add.right == unknown


def test_constant_branch_removes_dead_path() -> None:
    build = FunctionBuilder([("A", 64)])
    entry, taken, skipped = build.block(), build.block(), build.block()
    build.terminators[entry.id] = Branch(Const(1, 8), taken.id, skipped.id, Origin(0x1000, 0))
    build.returns(taken, Const(1, 64))
    build.returns(skipped, Const(2, 64))
    function = simplify_cfg(build.finish(("R",)))
    assert len(function.blocks) == 1
    assert _returned(function) == Const(1, 64)
    assert not isinstance(function.blocks[0].terminator, Jump | Branch)


def test_interfaces_pass_through_unwritten_registers() -> None:
    program = ProgramBuilder()
    program.code(0x2000, [op("INT_ADD", [reg("RDI"), const(1, 8)], reg("RAX")), *ret()])
    program.function("increment", 0x2000)
    after = program.code(0x1000, [op("COPY", [const(5, 8)], reg("RBP"))])
    after = program.code(after, call(0x2000, after + 12), length=12)
    program.code(after, [op("INT_ADD", [reg("RAX"), reg("RBP")], reg("RAX")), *ret()])
    program.function("caller", 0x1000)
    module = trim_interfaces(lift_export(program.build()).module)
    assert validate_module(module) == []
    increment = module.function_named("increment")
    assert increment is not None
    assert [item.register for item in increment.inputs] == ["RSP", "RDI"]
    assert increment.output_registers == ("RAX", "RSP")
    simplified = simplify_module(module)
    caller = simplified.function_named("caller")
    assert caller is not None
    adds = [
        item
        for block in caller.blocks
        for item in block.operations
        if isinstance(item, BinaryOp) and item.right == Const(5, 64)
    ]
    assert adds, "RBP survives the call as the constant 5"


# -- random program equivalence --------------------------------------------------------------

BINARY = [
    BinaryOpcode.ADD,
    BinaryOpcode.SUB,
    BinaryOpcode.MUL,
    BinaryOpcode.AND,
    BinaryOpcode.OR,
    BinaryOpcode.XOR,
    BinaryOpcode.SHIFT_LEFT,
    BinaryOpcode.LOGICAL_SHIFT_RIGHT,
    BinaryOpcode.ARITHMETIC_SHIFT_RIGHT,
    BinaryOpcode.EQUAL,
    BinaryOpcode.SIGNED_LESS,
    BinaryOpcode.UNSIGNED_LESS_EQUAL,
    BinaryOpcode.UNSIGNED_CARRY,
    BinaryOpcode.SIGNED_BORROW,
    BinaryOpcode.UNSIGNED_DIV,
    BinaryOpcode.SIGNED_REM,
]
UNARY = [
    UnaryOpcode.BITWISE_NOT,
    UnaryOpcode.TWOS_COMPLEMENT,
    UnaryOpcode.ZERO_EXTEND,
    UnaryOpcode.SIGN_EXTEND,
    UnaryOpcode.TRUNCATE,
    UnaryOpcode.POPCOUNT,
]
WIDTHS = [8, 16, 32, 64]


@st.composite
def programs(draw: st.DrawFn) -> Function:
    build = FunctionBuilder([("A", 64), ("B", 64)])
    block = build.block()
    pool: list[Operand] = [build.input("A"), build.input("B")]

    def pick(width: int | None = None) -> Operand:
        candidates = [value for value in pool if width is None or value.width == width]
        if candidates and draw(st.booleans()):
            # Prefer recent values so operations chain into foldable shapes.
            candidates = candidates[-2:]
        if not candidates or draw(st.integers(0, 5)) == 0:
            width = width or draw(st.sampled_from(WIDTHS))
            return Const(draw(st.integers(0, (1 << width) - 1) | st.sampled_from([0, 1])), width)
        return draw(st.sampled_from(candidates))

    for _ in range(draw(st.integers(1, 14))):
        kind = draw(st.integers(0, 3))
        if kind == 0:
            left = pool[-1] if draw(st.booleans()) else pick()
            opcode = draw(st.sampled_from(BINARY))
            if draw(st.booleans()):
                # Constant right operands are what most identities and merges key on.
                interesting = [0, 1, 2, 7, (1 << left.width) - 1, 1 << (left.width - 1)]
                value = draw(st.sampled_from(interesting) | st.integers(0, (1 << left.width) - 1))
                right = Const(value, left.width)
            else:
                right = pick(left.width)
            if isinstance(left, Const) and isinstance(right, Const):
                continue
            comparison = opcode in (
                BinaryOpcode.EQUAL,
                BinaryOpcode.SIGNED_LESS,
                BinaryOpcode.UNSIGNED_LESS_EQUAL,
                BinaryOpcode.UNSIGNED_CARRY,
                BinaryOpcode.SIGNED_BORROW,
            )
            pool.append(block.binary(opcode, left, right, 8 if comparison else left.width))
        elif kind == 1:
            operand = pick()
            if isinstance(operand, Const):
                continue
            opcode = draw(st.sampled_from(UNARY))
            wider = [width for width in WIDTHS if width > operand.width]
            narrower = [width for width in WIDTHS if width < operand.width]
            if opcode in (UnaryOpcode.ZERO_EXTEND, UnaryOpcode.SIGN_EXTEND):
                if not wider:
                    continue
                pool.append(block.unary(opcode, operand, draw(st.sampled_from(wider))))
            elif opcode is UnaryOpcode.TRUNCATE:
                if not narrower:
                    continue
                pool.append(block.unary(opcode, operand, draw(st.sampled_from(narrower))))
            else:
                pool.append(
                    block.unary(opcode, operand, 8 if opcode is UnaryOpcode.POPCOUNT else 0)
                )
        elif kind == 2:
            operand = pick()
            if isinstance(operand, Const) or operand.width == 8:
                continue
            width = draw(st.sampled_from([w for w in WIDTHS if w < operand.width]))
            low_bit = draw(st.integers(0, operand.width - width))
            pool.append(block.subpiece(operand, low_bit, width))
        else:
            high, low = pick(), pick()
            if high.width + low.width > 64 or (isinstance(high, Const) and isinstance(low, Const)):
                continue
            pool.append(block.piece(high, low))
    # Fold every generated value into the result so none of them is dead code.
    result: Operand = Const(0, 64)
    for value in pool[2:]:
        if value.width < 64:
            value = block.unary(UnaryOpcode.ZERO_EXTEND, value, 64)
        mixed = block.binary(BinaryOpcode.MUL, result, Const(0x9E3779B97F4A7C15, 64))
        result = block.binary(BinaryOpcode.XOR, mixed, value)
    build.returns(block, result)
    return build.finish(("R",))


def _outcome(module: Module, function: Function, a: int, b: int) -> int | FaultKind:
    memory = ConcreteMemory(Endianness.LITTLE)
    memory.map(Mapping("scratch", 0, 16, True, True, None))
    try:
        return Interpreter(module, memory).call(function, {"A": a, "B": b}, None)["R"]
    except ExecutionError as error:
        return error.kind


@settings(max_examples=300, deadline=None)
@given(
    programs(),
    st.lists(st.tuples(st.integers(0, 2**64 - 1), st.integers(0, 255)), min_size=4, max_size=4),
)
def test_simplification_preserves_random_programs(
    function: Function, inputs: list[tuple[int, int]]
) -> None:
    module = module_for(function, registers=REGISTERS)
    assert validate_function(function, dict(REGISTERS), 64) == []
    simplified = simplify_function(module, function)
    assert validate_function(simplified, dict(REGISTERS), 64) == []
    for a, b in [*inputs, (0, 0), (2**64 - 1, 1)]:
        assert _outcome(module, function, a, b) == _outcome(module, simplified, a, b)

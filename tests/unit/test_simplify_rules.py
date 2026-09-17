"""Every folding rule, checked for equivalence on edge values at several widths."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from ppy_rev.execution.interpreter import ExecutionError, FaultKind, Interpreter
from ppy_rev.execution.memory import ConcreteMemory
from ppy_rev.ir.model import COMPARISON_OPCODES, Const, Endianness, Function, Operand, Var
from ppy_rev.ir.model import BinaryOpcode as B
from ppy_rev.ir.model import UnaryOpcode as U
from ppy_rev.simplify.pipeline import simplify_function
from support.revir import BlockBuilder, FunctionBuilder, module_for

type Pattern = Callable[[BlockBuilder, Var, Var], Operand]

REGISTERS = (("A", 64), ("B", 64), ("R", 64))
EDGES = [
    *(0, 1, 2, 3, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000),
    0xFFFFFFFF,
    0x7FFFFFFFFFFFFFFF,
    0x8000000000000000,
    0xFFFFFFFFFFFFFFFF,
    0x123456789ABCDEF0,
]


def narrow(block: BlockBuilder, value: Var, width: int) -> Var:
    return value if width == 64 else block.unary(U.TRUNCATE, value, width)


def binary_const(opcode: B, constant: int) -> Callable[[int], Pattern]:
    def at(width: int) -> Pattern:
        def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
            del b
            x = narrow(block, a, width)
            output = 8 if opcode in COMPARISON_OPCODES else width
            return block.binary(opcode, x, Const(constant % (1 << width), width), output)

        return build

    return at


def chain(inner: B, c1: int, outer: B, c2: int) -> Callable[[int], Pattern]:
    def at(width: int) -> Pattern:
        def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
            del b
            x = narrow(block, a, width)
            first = block.binary(inner, x, Const(c1 % (1 << width), width))
            return block.binary(outer, first, Const(c2 % (1 << width), width))

        return build

    return at


def same_operands(opcode: B) -> Callable[[int], Pattern]:
    comparison = opcode in COMPARISON_OPCODES

    def at(width: int) -> Pattern:
        def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
            del b
            x = narrow(block, a, width)
            return block.binary(opcode, x, x, 8 if comparison else width)

        return build

    return at


def unary_twice(opcode: U) -> Callable[[int], Pattern]:
    def at(width: int) -> Pattern:
        def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
            del b
            x = narrow(block, a, width)
            return block.unary(opcode, block.unary(opcode, x))

        return build

    return at


def extension_then_truncate(extension: U, source: int, middle: int, final: int) -> Pattern:
    def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
        del b
        x = narrow(block, a, source)
        return block.unary(U.TRUNCATE, block.unary(extension, x, middle), final)

    return build


def nested_extension(extension: U) -> Pattern:
    def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
        del b
        x = narrow(block, a, 8)
        return block.unary(extension, block.unary(extension, x, 16), 64)

    return build


def piece_then(select: Callable[[BlockBuilder, Var], Operand], high: int, low: int) -> Pattern:
    def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
        joined = block.piece(narrow(block, a, high), narrow(block, b, low))
        return select(block, joined)

    return build


def subpiece_of_extension(extension: U, low_bit: int, width: int) -> Pattern:
    def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
        del b
        extended = block.unary(extension, narrow(block, a, 16), 64)
        return block.subpiece(extended, low_bit, width)

    return build


def rejoin(split: int) -> Pattern:
    def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
        del b
        high = block.subpiece(a, split, 64 - split)
        low = block.unary(U.TRUNCATE, a, split)
        return block.piece(high, low)

    return build


def nested_subpiece(outer_low: int, outer_width: int) -> Pattern:
    def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
        del b
        inner = block.subpiece(a, 8, 32)
        return block.subpiece(inner, outer_low, outer_width)

    return build


def zero_high_piece(block: BlockBuilder, a: Var, b: Var) -> Operand:
    del b
    return block.piece(Const(0, 32), narrow(block, a, 32))


def truncated_arithmetic(opcode: B, extension: U) -> Pattern:
    def build(block: BlockBuilder, a: Var, b: Var) -> Operand:
        left = block.unary(extension, narrow(block, a, 8), 32)
        right = block.unary(U.ZERO_EXTEND, narrow(block, b, 8), 32)
        mixed = block.binary(opcode, block.binary(opcode, left, Const(0x1C3, 32)), right)
        return block.unary(U.TRUNCATE, mixed, 8)

    return build


def commuted_constant(block: BlockBuilder, a: Var, b: Var) -> Operand:
    del b
    return block.binary(B.SUB, block.binary(B.ADD, Const(5, 64), a), Const(9, 64))


PATTERNS: dict[str, Pattern] = {}
for width in (8, 32, 64):
    for name, factory in {
        "add0": binary_const(B.ADD, 0),
        "sub0": binary_const(B.SUB, 0),
        "or0": binary_const(B.OR, 0),
        "xor0": binary_const(B.XOR, 0),
        "shl0": binary_const(B.SHIFT_LEFT, 0),
        "shr0": binary_const(B.LOGICAL_SHIFT_RIGHT, 0),
        "sar0": binary_const(B.ARITHMETIC_SHIFT_RIGHT, 0),
        "and0": binary_const(B.AND, 0),
        "and_full": binary_const(B.AND, -1),
        "or_full": binary_const(B.OR, -1),
        "mul1": binary_const(B.MUL, 1),
        "mul0": binary_const(B.MUL, 0),
        "udiv1": binary_const(B.UNSIGNED_DIV, 1),
        "sdiv1": binary_const(B.SIGNED_DIV, 1),
        "urem1": binary_const(B.UNSIGNED_REM, 1),
        "ult0": binary_const(B.UNSIGNED_LESS, 0),
        "ule0": binary_const(B.UNSIGNED_LESS_EQUAL, 0),
        "slt0": binary_const(B.SIGNED_LESS, 0),
        "sle0": binary_const(B.SIGNED_LESS_EQUAL, 0),
        "eq0": binary_const(B.EQUAL, 0),
        "ne_full": binary_const(B.NOT_EQUAL, -1),
        "ult_full": binary_const(B.UNSIGNED_LESS, -1),
        "carry0": binary_const(B.UNSIGNED_CARRY, 0),
        "scarry0": binary_const(B.SIGNED_CARRY, 0),
        "sborrow0": binary_const(B.SIGNED_BORROW, 0),
        "sub_self": same_operands(B.SUB),
        "xor_self": same_operands(B.XOR),
        "and_self": same_operands(B.AND),
        "or_self": same_operands(B.OR),
        "eq_self": same_operands(B.EQUAL),
        "ne_self": same_operands(B.NOT_EQUAL),
        "ult_self": same_operands(B.UNSIGNED_LESS),
        "ule_self": same_operands(B.UNSIGNED_LESS_EQUAL),
        "slt_self": same_operands(B.SIGNED_LESS),
        "sle_self": same_operands(B.SIGNED_LESS_EQUAL),
        "add_add": chain(B.ADD, 3, B.ADD, 5),
        "add_sub": chain(B.ADD, 3, B.SUB, 5),
        "sub_add": chain(B.SUB, 7, B.ADD, 2),
        "sub_sub": chain(B.SUB, 7, B.SUB, 250),
        "add_sub_cancel": chain(B.ADD, 9, B.SUB, 9),
        "and_and": chain(B.AND, 0xF0F0, B.AND, 0x3C3C),
        "or_or": chain(B.OR, 0x0101, B.OR, 0x8080),
        "xor_xor": chain(B.XOR, 0x55, B.XOR, 0xFF),
        "mul_mul": chain(B.MUL, 0x10001, B.MUL, 0xDEAD),
        "not_not": unary_twice(U.BITWISE_NOT),
        "neg_neg": unary_twice(U.TWOS_COMPLEMENT),
    }.items():
        PATTERNS[f"{name}-{width}"] = factory(width)
PATTERNS.update(
    {
        "bool_not_not": unary_twice(U.BOOLEAN_NOT)(8),
        "zext_trunc_same": extension_then_truncate(U.ZERO_EXTEND, 16, 64, 16),
        "zext_trunc_narrower": extension_then_truncate(U.ZERO_EXTEND, 32, 64, 8),
        "zext_trunc_wider": extension_then_truncate(U.ZERO_EXTEND, 8, 64, 32),
        "sext_trunc_same": extension_then_truncate(U.SIGN_EXTEND, 16, 64, 16),
        "sext_trunc_wider": extension_then_truncate(U.SIGN_EXTEND, 8, 64, 32),
        "zext_zext": nested_extension(U.ZERO_EXTEND),
        "sext_sext": nested_extension(U.SIGN_EXTEND),
        "trunc_piece_low": piece_then(lambda b, j: b.unary(U.TRUNCATE, j, 16), 32, 16),
        "trunc_piece_narrow": piece_then(lambda b, j: b.unary(U.TRUNCATE, j, 8), 32, 16),
        "trunc_piece_wide": piece_then(lambda b, j: b.unary(U.TRUNCATE, j, 32), 32, 16),
        "subpiece_piece_high": piece_then(lambda b, j: b.subpiece(j, 16, 32), 32, 16),
        "subpiece_piece_inner_high": piece_then(lambda b, j: b.subpiece(j, 20, 8), 32, 16),
        "subpiece_piece_low": piece_then(lambda b, j: b.subpiece(j, 4, 8), 32, 16),
        "subpiece_piece_straddle": piece_then(lambda b, j: b.subpiece(j, 8, 16), 32, 16),
        "subpiece_zext_above": subpiece_of_extension(U.ZERO_EXTEND, 32, 16),
        "subpiece_zext_within": subpiece_of_extension(U.ZERO_EXTEND, 4, 8),
        "subpiece_zext_straddle": subpiece_of_extension(U.ZERO_EXTEND, 8, 16),
        "subpiece_sext_above": subpiece_of_extension(U.SIGN_EXTEND, 32, 16),
        "subpiece_sext_within": subpiece_of_extension(U.SIGN_EXTEND, 4, 8),
        "rejoin_32": rejoin(32),
        "rejoin_8": rejoin(8),
        "nested_subpiece": nested_subpiece(4, 16),
        "nested_subpiece_top": nested_subpiece(16, 16),
        "zero_high_piece": zero_high_piece,
        **{
            f"truncate_{opcode}_{extension}": truncated_arithmetic(opcode, extension)
            for opcode in (B.ADD, B.SUB, B.MUL, B.AND, B.OR, B.XOR, B.SHIFT_LEFT, B.UNSIGNED_DIV)
            for extension in (U.ZERO_EXTEND, U.SIGN_EXTEND)
        },
        "commuted_constant": commuted_constant,
    }
)


def _function(pattern: Pattern) -> Function:
    build = FunctionBuilder([("A", 64), ("B", 64)])
    block = build.block()
    result = pattern(block, build.input("A"), build.input("B"))
    if result.width < 64:
        result = block.unary(U.ZERO_EXTEND, result, 64)
    build.returns(block, result)
    return build.finish(("R",))


def _run(function: Function, a: int, b: int) -> int | FaultKind:
    module = module_for(function, registers=REGISTERS)
    try:
        return Interpreter(module, ConcreteMemory(Endianness.LITTLE)).call(
            function, {"A": a, "B": b}, None
        )["R"]
    except ExecutionError as error:
        return error.kind


@pytest.mark.parametrize("name", sorted(PATTERNS))
def test_rule_preserves_semantics(name: str) -> None:
    function = _function(PATTERNS[name])
    simplified = simplify_function(module_for(function, registers=REGISTERS), function)
    for a in EDGES:
        for b in EDGES[::4]:
            assert _run(simplified, a, b) == _run(function, a, b), (name, hex(a), hex(b))

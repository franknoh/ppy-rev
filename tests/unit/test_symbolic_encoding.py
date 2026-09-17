"""Symbolic encodings, the expression evaluator, and Z3 all agree with the reference semantics."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ppy_rev.ir import semantics
from ppy_rev.ir.model import DIVISION_OPCODES, BinaryOpcode, UnaryOpcode, mask
from ppy_rev.solver.backend import Status
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.symbolic import encode
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.evaluate import evaluate

BINARY = [
    opcode
    for opcode in BinaryOpcode
    if opcode not in (BinaryOpcode.POINTER_ADD, BinaryOpcode.POINTER_SUB)
]
COMPARISONS = {
    BinaryOpcode.EQUAL,
    BinaryOpcode.NOT_EQUAL,
    BinaryOpcode.UNSIGNED_LESS,
    BinaryOpcode.UNSIGNED_LESS_EQUAL,
    BinaryOpcode.SIGNED_LESS,
    BinaryOpcode.SIGNED_LESS_EQUAL,
    BinaryOpcode.UNSIGNED_CARRY,
    BinaryOpcode.SIGNED_CARRY,
    BinaryOpcode.SIGNED_BORROW,
}
BOOLEANS = {BinaryOpcode.BOOLEAN_AND, BinaryOpcode.BOOLEAN_OR, BinaryOpcode.BOOLEAN_XOR}


def _values(width: int) -> st.SearchStrategy[int]:
    edges = [0, 1, 2, mask(width), 1 << (width - 1), (1 << (width - 1)) - 1]
    return st.sampled_from(edges) | st.integers(0, mask(width))


@st.composite
def binary_cases(draw: st.DrawFn) -> tuple[BinaryOpcode, int, int, int, int]:
    opcode = draw(st.sampled_from(BINARY))
    width = 8 if opcode in BOOLEANS else draw(st.sampled_from([8, 16, 32, 64]))
    left = draw(_values(width))
    if opcode in BOOLEANS:
        left = draw(st.integers(0, 1) | _values(8))
    shift = opcode in (
        BinaryOpcode.SHIFT_LEFT,
        BinaryOpcode.LOGICAL_SHIFT_RIGHT,
        BinaryOpcode.ARITHMETIC_SHIFT_RIGHT,
    )
    right_width = draw(st.sampled_from([8, width, 64])) if shift else width
    right = draw(
        _values(right_width) | st.integers(0, 2 * width) if shift else _values(right_width)
    )
    right &= mask(right_width)
    return opcode, width, left, right, right_width


def _output_width(opcode: BinaryOpcode, width: int) -> int:
    return 8 if opcode in COMPARISONS else width


@settings(max_examples=2000, deadline=None)
@given(binary_cases(), st.booleans())
def test_binary_encoding_matches_semantics(
    case: tuple[BinaryOpcode, int, int, int, int], symbolic: bool
) -> None:
    opcode, width, left, right, right_width = case
    if opcode in DIVISION_OPCODES and right == 0:
        return
    expected = semantics.binary(opcode, left, right, width)
    left_expr = sx.symbol("a", width) if symbolic else sx.const(left, width)
    right_expr = sx.symbol("b", right_width) if symbolic else sx.const(right, right_width)
    encoded = encode.binary(opcode, left_expr, right_expr, _output_width(opcode, width))
    assert encoded.width == _output_width(opcode, width)
    assert evaluate(encoded, {"a": left, "b": right}) == expected


@st.composite
def unary_cases(draw: st.DrawFn) -> tuple[UnaryOpcode, int, int, int]:
    opcode = draw(st.sampled_from(list(UnaryOpcode)))
    width = draw(st.sampled_from([8, 16, 32, 64]))
    value = draw(_values(width))
    match opcode:
        case UnaryOpcode.ZERO_EXTEND | UnaryOpcode.SIGN_EXTEND:
            output = draw(st.sampled_from([w for w in (16, 32, 64, 128) if w > width]))
        case UnaryOpcode.TRUNCATE:
            if width == 8:
                width, value = 16, value
            output = draw(st.sampled_from([w for w in (8, 16, 32) if w < width]))
        case UnaryOpcode.POPCOUNT | UnaryOpcode.COUNT_LEADING_ZEROS:
            output = draw(st.sampled_from([8, 32]))
        case UnaryOpcode.BOOLEAN_NOT:
            width, output, value = 8, 8, draw(st.integers(0, 1) | _values(8))
        case _:
            output = width
    return opcode, width, value & mask(width), output


@settings(max_examples=1000, deadline=None)
@given(unary_cases(), st.booleans())
def test_unary_encoding_matches_semantics(
    case: tuple[UnaryOpcode, int, int, int], symbolic: bool
) -> None:
    opcode, width, value, output = case
    operand = sx.symbol("a", width) if symbolic else sx.const(value, width)
    encoded = encode.unary(opcode, operand, output)
    assert encoded.width == output
    assert evaluate(encoded, {"a": value}) == semantics.unary(opcode, value, width, output)


@settings(max_examples=150, deadline=None)
@given(binary_cases())
def test_z3_agrees_with_the_evaluator(case: tuple[BinaryOpcode, int, int, int, int]) -> None:
    opcode, width, left, right, right_width = case
    if opcode in DIVISION_OPCODES and right == 0:
        return
    a, b = sx.symbol("a", width), sx.symbol("b", right_width)
    encoded = encode.binary(opcode, a, b, _output_width(opcode, width))
    result = sx.symbol("result", encoded.width)
    session = Z3Backend().session()
    session.add(sx.equal(a, sx.const(left, width)))
    session.add(sx.equal(b, sx.const(right, right_width)))
    session.add(sx.equal(result, encoded))
    check = session.check(symbols=[result])
    assert check.status is Status.SAT
    assert check.model["result"] == semantics.binary(opcode, left, right, width)


@st.composite
def trees(draw: st.DrawFn, depth: int = 4) -> sx.Expr:
    width = draw(st.sampled_from([8, 32]))
    return draw(_tree(width, depth))


type Builder = Callable[[sx.Expr, sx.Expr], sx.Expr]
BINARY_BUILDERS: list[Builder] = [
    sx.add,
    sx.sub,
    sx.mul,
    sx.bitwise_and,
    sx.bitwise_or,
    sx.bitwise_xor,
    sx.shift_left,
    sx.logical_shift_right,
    sx.arithmetic_shift_right,
]
COMPARISON_BUILDERS: list[Builder] = [sx.equal, sx.unsigned_less, sx.signed_less_equal]


def _apply(builder: Builder, left: sx.Expr, right: sx.Expr) -> sx.Expr:
    return builder(left, right)


def _select(comparison: Builder, left: sx.Expr, right: sx.Expr) -> sx.Expr:
    return sx.ite(comparison(left, right), left, right)


def _round_trip_extension(value: sx.Expr) -> sx.Expr:
    return sx.extract(sx.zero_extend(value, value.width * 2), 0, value.width)


def _middle_of_concat(high: sx.Expr, low: sx.Expr) -> sx.Expr:
    return sx.extract(sx.concat(high, low), low.width // 2, low.width)


def _tree(width: int, depth: int) -> st.SearchStrategy[sx.Expr]:
    leaf = st.one_of(
        st.builds(sx.const, _values(width), st.just(width)),
        st.sampled_from([sx.symbol(f"s{width}_{index}", width) for index in range(2)]),
    )
    if depth == 0:
        return leaf
    child = _tree(width, depth - 1)
    return st.one_of(
        leaf,
        st.builds(_apply, st.sampled_from(BINARY_BUILDERS), child, child),
        st.builds(sx.bitwise_not, child),
        st.builds(sx.negate, child),
        st.builds(_select, st.sampled_from(COMPARISON_BUILDERS), child, child),
        st.builds(_round_trip_extension, child),
        st.builds(_middle_of_concat, child, child),
    )


@settings(max_examples=400, deadline=None)
@given(trees(), st.lists(st.integers(0, 2**64 - 1), min_size=4, max_size=4))
def test_expression_trees_evaluate_consistently_in_z3(tree: sx.Expr, values: list[int]) -> None:
    assignment = {
        f"s{width}_{index}": values[index % 4] & mask(width)
        for width in (8, 32)
        for index in range(2)
    }
    session = Z3Backend().session()
    for symbol in sx.symbols(tree):
        session.add(sx.equal(symbol, sx.const(assignment[symbol.name], symbol.width)))
    result = sx.symbol("result", tree.width)
    session.add(sx.equal(result, tree))
    check = session.check(symbols=[result])
    assert check.status is Status.SAT
    assert check.model["result"] == evaluate(tree, assignment)


@pytest.mark.parametrize("width", [8, 64])
def test_hash_consing_shares_structure(width: int) -> None:
    x = sx.symbol("x", width)
    assert sx.add(x, sx.const(1, width)) is sx.add(x, sx.const(1, width))
    assert sx.sub(sx.add(x, sx.const(5, width)), sx.const(5, width)) is x
    assert sx.equal(sx.bitwise_xor(x, sx.const(0x41, width)), sx.const(0x12, width)) is sx.equal(
        x, sx.const(0x53, width)
    )

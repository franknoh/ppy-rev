from __future__ import annotations

import math
import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ppy_rev.ir import semantics
from ppy_rev.ir.model import BinaryOpcode, UnaryOpcode
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.symbolic import encode
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.evaluate import evaluate

BINARY = [
    BinaryOpcode.FLOAT_ADD,
    BinaryOpcode.FLOAT_SUB,
    BinaryOpcode.FLOAT_MUL,
    BinaryOpcode.FLOAT_DIV,
    BinaryOpcode.FLOAT_EQUAL,
    BinaryOpcode.FLOAT_NOT_EQUAL,
    BinaryOpcode.FLOAT_LESS,
    BinaryOpcode.FLOAT_LESS_EQUAL,
]
UNARY = [
    UnaryOpcode.FLOAT_NEGATE,
    UnaryOpcode.FLOAT_ABSOLUTE,
    UnaryOpcode.FLOAT_SQUARE_ROOT,
    UnaryOpcode.FLOAT_IS_NAN,
    UnaryOpcode.FLOAT_CEILING,
    UnaryOpcode.FLOAT_FLOOR,
    UnaryOpcode.FLOAT_ROUND,
]
numbers = st.floats(allow_nan=True, allow_infinity=True, width=64)


def _bits(value: float, width: int = 64) -> int:
    return int.from_bytes(struct.pack("<d" if width == 64 else "<f", value), "little")


def _python(opcode: BinaryOpcode, left: float, right: float) -> float | bool:
    match opcode:
        case BinaryOpcode.FLOAT_ADD:
            return left + right
        case BinaryOpcode.FLOAT_SUB:
            return left - right
        case BinaryOpcode.FLOAT_MUL:
            return left * right
        case BinaryOpcode.FLOAT_EQUAL:
            return left == right
        case BinaryOpcode.FLOAT_NOT_EQUAL:
            return left != right
        case BinaryOpcode.FLOAT_LESS:
            return left < right
        case _:
            return left <= right


@settings(max_examples=200, deadline=None)
@given(
    numbers,
    numbers,
    st.sampled_from([item for item in BINARY if item is not BinaryOpcode.FLOAT_DIV]),
)
def test_binary_semantics_match_python(left: float, right: float, opcode: BinaryOpcode) -> None:
    """Python's own float arithmetic is IEEE-754 binary64, so it is the reference."""
    result = semantics.binary(opcode, _bits(left), _bits(right), 64)
    expected = _python(opcode, left, right)
    if isinstance(expected, bool):
        assert result == int(expected)
    elif math.isnan(expected):
        assert math.isnan(semantics.to_float(result, 64))
    else:
        assert semantics.to_float(result, 64) == expected


@settings(max_examples=100, deadline=None)
@given(numbers, numbers)
def test_division_by_zero_is_an_infinity_not_an_exception(left: float, right: float) -> None:
    result = semantics.to_float(
        semantics.binary(BinaryOpcode.FLOAT_DIV, _bits(left), _bits(right), 64), 64
    )
    if right != 0 and not math.isnan(left) and not math.isnan(right):
        with_python = left / right if right != 0 else None
        if with_python is not None and not math.isnan(with_python):
            assert result == with_python
    elif right == 0 and left not in (0.0, -0.0) and not math.isnan(left):
        assert math.isinf(result)
    else:
        assert math.isnan(result)


@settings(max_examples=200, deadline=None)
@given(numbers, st.sampled_from(BINARY))
def test_the_symbolic_encoding_agrees_with_the_semantics(
    value: float, opcode: BinaryOpcode
) -> None:
    other = 1.5
    left, right = sx.const(_bits(value), 64), sx.const(_bits(other), 64)
    width = 8 if "equal" in opcode or "less" in opcode else 64
    encoded = encode.binary(opcode, left, right, width)
    assert evaluate(encoded, {}) == semantics.binary(opcode, left.value, right.value, 64)


@settings(max_examples=150, deadline=None)
@given(numbers, st.sampled_from(UNARY))
def test_unary_encoding_agrees_with_the_semantics(value: float, opcode: UnaryOpcode) -> None:
    operand = sx.const(_bits(value), 64)
    width = 8 if opcode is UnaryOpcode.FLOAT_IS_NAN else 64
    encoded = encode.unary(opcode, operand, width)
    assert evaluate(encoded, {}) == semantics.unary(opcode, operand.value, 64, width)


@settings(max_examples=100, deadline=None)
@given(st.integers(-(2**31), 2**31 - 1))
def test_conversions_round_trip_through_the_solver(value: int) -> None:
    """`(double)n` then back: what a compiler emits for an int compared with a double."""
    encoded = encode.unary(UnaryOpcode.FLOAT_FROM_SIGNED, sx.const(value & 0xFFFFFFFF, 32), 64)
    back = encode.unary(UnaryOpcode.FLOAT_TO_SIGNED, encoded, 32)
    assert evaluate(back, {}) == value & 0xFFFFFFFF


def test_the_solver_finds_an_input_satisfying_a_float_constraint() -> None:
    """`x * 1.5 + 0.25` lands in (63, 64) exactly when x is 42."""
    session = Z3Backend().session()
    symbol = sx.symbol("n", 32)
    scaled = sx.float_add(
        sx.float_mul(sx.float_from_signed(symbol, 64), sx.const(_bits(1.5), 64)),
        sx.const(_bits(0.25), 64),
    )
    conditions = [
        sx.float_less(sx.const(_bits(63.0), 64), scaled),
        sx.float_less(scaled, sx.const(_bits(64.0), 64)),
    ]
    result = session.check(conditions, [symbol])
    assert result.model[symbol.name] == 42


def test_an_unmodeled_float_width_is_refused() -> None:
    with pytest.raises(ValueError, match="80-bit"):
        sx.float_add(sx.symbol("a", 80), sx.symbol("b", 80))
    with pytest.raises(semantics.UnsupportedFloatWidthError):
        semantics.to_float(0, 80)

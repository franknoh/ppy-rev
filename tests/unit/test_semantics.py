from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from ppy_rev.ir.model import BinaryOpcode, UnaryOpcode, mask
from ppy_rev.ir.semantics import (
    DivisionByZeroError,
    binary,
    from_signed,
    piece,
    subpiece,
    to_signed,
    unary,
)

WIDTHS = st.sampled_from([8, 16, 32, 64])


@st.composite
def operands(draw: st.DrawFn) -> tuple[int, int, int]:
    width = draw(WIDTHS)
    edge = st.sampled_from([0, 1, mask(width), 1 << (width - 1), (1 << (width - 1)) - 1])
    value = st.integers(0, mask(width)) | edge
    return width, draw(value), draw(value)


def test_edge_values() -> None:
    assert binary(BinaryOpcode.ADD, 255, 1, 8) == 0
    assert binary(BinaryOpcode.SUB, 0, 1, 32) == 0xFFFFFFFF
    assert binary(BinaryOpcode.MUL, 0x8000, 2, 16) == 0
    int_min = 0x80000000
    assert binary(BinaryOpcode.SIGNED_DIV, int_min, 0xFFFFFFFF, 32) == int_min
    assert binary(BinaryOpcode.SIGNED_REM, int_min, 0xFFFFFFFF, 32) == 0
    assert binary(BinaryOpcode.SIGNED_DIV, from_signed(-7, 8), 2, 8) == from_signed(-3, 8)
    assert binary(BinaryOpcode.SIGNED_REM, from_signed(-7, 8), 2, 8) == from_signed(-1, 8)
    assert binary(BinaryOpcode.SIGNED_REM, 7, from_signed(-2, 8), 8) == 1
    assert binary(BinaryOpcode.SIGNED_LESS, 0xFF, 0, 8) == 1
    assert binary(BinaryOpcode.UNSIGNED_LESS, 0xFF, 0, 8) == 0
    assert binary(BinaryOpcode.SIGNED_CARRY, 0x7F, 1, 8) == 1
    assert binary(BinaryOpcode.UNSIGNED_CARRY, 0xFF, 1, 8) == 1
    assert binary(BinaryOpcode.SIGNED_BORROW, 0x80, 1, 8) == 1
    assert binary(BinaryOpcode.ARITHMETIC_SHIFT_RIGHT, 0x80, 100, 8) == 0xFF
    assert binary(BinaryOpcode.SHIFT_LEFT, 1, 64, 64) == 0
    assert unary(UnaryOpcode.SIGN_EXTEND, 0x80, 8, 32) == 0xFFFFFF80
    assert unary(UnaryOpcode.COUNT_LEADING_ZEROS, 0, 32, 8) == 32
    assert unary(UnaryOpcode.BOOLEAN_NOT, 2, 8, 8) == 3  # bytewise, as in Ghidra's emulator
    assert subpiece(0x1122334455667788, 8, 16) == 0x6677
    assert piece(0xAB, 0xCD, 8) == 0xABCD


@pytest.mark.parametrize(
    "opcode",
    [
        BinaryOpcode.UNSIGNED_DIV,
        BinaryOpcode.SIGNED_DIV,
        BinaryOpcode.UNSIGNED_REM,
        BinaryOpcode.SIGNED_REM,
    ],
)
def test_division_by_zero_faults(opcode: BinaryOpcode) -> None:
    with pytest.raises(DivisionByZeroError):
        binary(opcode, 5, 0, 32)


@given(operands())
def test_wrapping_arithmetic(case: tuple[int, int, int]) -> None:
    width, a, b = case
    assert binary(BinaryOpcode.ADD, a, b, width) == (a + b) % (1 << width)
    assert binary(BinaryOpcode.SUB, a, b, width) == (a - b) % (1 << width)
    assert binary(BinaryOpcode.MUL, a, b, width) == (a * b) % (1 << width)
    assert unary(UnaryOpcode.TWOS_COMPLEMENT, a, width, width) == (-a) % (1 << width)
    assert unary(UnaryOpcode.BITWISE_NOT, a, width, width) == mask(width) - a


@given(operands())
def test_signed_division_identity(case: tuple[int, int, int]) -> None:
    width, a, b = case
    if b == 0:
        return
    quotient = binary(BinaryOpcode.SIGNED_DIV, a, b, width)
    remainder = binary(BinaryOpcode.SIGNED_REM, a, b, width)
    assert (quotient * b + remainder) % (1 << width) == a
    signed_remainder = to_signed(remainder, width)
    assert abs(signed_remainder) < abs(to_signed(b, width))
    assert signed_remainder == 0 or (signed_remainder < 0) == (to_signed(a, width) < 0)
    assert binary(BinaryOpcode.UNSIGNED_DIV, a, b, width) == a // b
    assert binary(BinaryOpcode.UNSIGNED_REM, a, b, width) == a % b


@given(operands(), st.integers(0, 200))
def test_shifts(case: tuple[int, int, int], amount: int) -> None:
    width, a, _ = case
    left = binary(BinaryOpcode.SHIFT_LEFT, a, amount, width)
    logical = binary(BinaryOpcode.LOGICAL_SHIFT_RIGHT, a, amount, width)
    arithmetic = binary(BinaryOpcode.ARITHMETIC_SHIFT_RIGHT, a, amount, width)
    assert left == (a << amount) % (1 << width)
    assert logical == a >> amount
    assert to_signed(arithmetic, width) == to_signed(a, width) >> amount


@given(operands())
def test_comparisons_and_flags(case: tuple[int, int, int]) -> None:
    width, a, b = case
    sa, sb = to_signed(a, width), to_signed(b, width)
    limit = 1 << (width - 1)
    assert binary(BinaryOpcode.SIGNED_LESS, a, b, width) == int(sa < sb)
    assert binary(BinaryOpcode.SIGNED_LESS_EQUAL, a, b, width) == int(sa <= sb)
    assert binary(BinaryOpcode.UNSIGNED_LESS_EQUAL, a, b, width) == int(a <= b)
    assert binary(BinaryOpcode.UNSIGNED_CARRY, a, b, width) == int(a + b >= 1 << width)
    assert binary(BinaryOpcode.SIGNED_CARRY, a, b, width) == int(not -limit <= sa + sb < limit)
    assert binary(BinaryOpcode.SIGNED_BORROW, a, b, width) == int(not -limit <= sa - sb < limit)


@given(operands(), st.sampled_from([8, 16, 32, 64, 128]))
def test_extensions_truncations_and_counts(case: tuple[int, int, int], wider: int) -> None:
    width, a, _ = case
    assert from_signed(to_signed(a, width), width) == a
    if wider > width:
        extended = unary(UnaryOpcode.SIGN_EXTEND, a, width, wider)
        assert to_signed(extended, wider) == to_signed(a, width)
        assert unary(UnaryOpcode.TRUNCATE, extended, wider, width) == a
        assert unary(UnaryOpcode.ZERO_EXTEND, a, width, wider) == a
    assert unary(UnaryOpcode.POPCOUNT, a, width, 8) == bin(a).count("1")
    leading = unary(UnaryOpcode.COUNT_LEADING_ZEROS, a, width, 8)
    assert leading == width - len(bin(a)[2:].lstrip("0") or "")
    assert piece(subpiece(a, width // 2, width // 2), subpiece(a, 0, width // 2), width // 2) == a

"""Concrete semantics of RevIR operations on fixed-width values.

This is the reference definition every other consumer (the symbolic encoding, the PPy
emitter, simplification) is tested against. Values are Python integers in [0, 2**width).

Where p-code leaves behaviour open, RevIR decides explicitly:
- division and remainder by zero are faults (x86 raises #DE); callers must not continue;
- signed division overflow (MIN / -1) wraps to MIN, as Ghidra's emulator does;
- boolean operations act on whole bytes (`boolean_not x` is `x ^ 1`), as Ghidra's
  emulator does, which coincides with logical semantics on 0/1 inputs;
- shifts by at least the operand width yield 0 (or the sign fill for arithmetic shifts);
- floating-point values are IEEE-754 bit patterns in 32- or 64-bit values, computed with
  round-to-nearest-even and without traps: dividing by zero gives an infinity, an invalid
  operation gives a NaN, and any comparison with a NaN is false.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Callable

from ppy_rev.ir.model import (
    FLOAT_WIDTHS,
    BinaryOpcode,
    UnaryOpcode,
    mask,
)


class DivisionByZeroError(ArithmeticError):
    pass


def to_signed(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


def from_signed(value: int, width: int) -> int:
    return value & mask(width)


class UnsupportedFloatWidthError(ValueError):
    """A floating-point format RevIR does not model, such as x87's 80-bit extended."""


_FORMATS = {32: "<f", 64: "<d"}


def to_float(bits: int, width: int) -> float:
    """The IEEE-754 number a `width`-bit pattern stands for."""
    if width not in FLOAT_WIDTHS:
        raise UnsupportedFloatWidthError(f"{width}-bit floating point is not modeled")
    return float(struct.unpack(_FORMATS[width], bits.to_bytes(width // 8, "little"))[0])


def from_float(value: float, width: int) -> int:
    """`value` as a `width`-bit pattern, rounding to nearest even and saturating to infinity."""
    if width not in FLOAT_WIDTHS:
        raise UnsupportedFloatWidthError(f"{width}-bit floating point is not modeled")
    try:
        packed = struct.pack(_FORMATS[width], value)
    except OverflowError:  # binary32 cannot hold it; IEEE rounds such a result to infinity
        packed = struct.pack(_FORMATS[width], math.inf if value > 0 else -math.inf)
    return int.from_bytes(packed, "little")


def _float_binary(opcode: BinaryOpcode, left: int, right: int, width: int) -> int:
    first, second = to_float(left, width), to_float(right, width)
    match opcode:
        case BinaryOpcode.FLOAT_ADD:
            return from_float(first + second, width)
        case BinaryOpcode.FLOAT_SUB:
            return from_float(first - second, width)
        case BinaryOpcode.FLOAT_MUL:
            return from_float(first * second, width)
        case BinaryOpcode.FLOAT_DIV:
            return from_float(_divide(first, second), width)
        case BinaryOpcode.FLOAT_EQUAL:
            return int(first == second)
        case BinaryOpcode.FLOAT_NOT_EQUAL:
            return int(first != second)
        case BinaryOpcode.FLOAT_LESS:
            return int(first < second)
        case _:
            return int(first <= second)


def _divide(left: float, right: float) -> float:
    """IEEE division: by zero gives an infinity, and zero over zero a NaN, without trapping."""
    if right != 0:
        return left / right
    if left != left or left == 0:
        return math.nan
    return math.copysign(math.inf, left) * math.copysign(1.0, right)


def _float_unary(opcode: UnaryOpcode, value: int, input_width: int, output_width: int) -> int:
    if opcode is UnaryOpcode.FLOAT_FROM_SIGNED:
        return from_float(float(to_signed(value, input_width)), output_width)
    number = to_float(value, input_width)
    match opcode:
        case UnaryOpcode.FLOAT_NEGATE:
            return from_float(-number, input_width)
        case UnaryOpcode.FLOAT_ABSOLUTE:
            return from_float(abs(number), input_width)
        case UnaryOpcode.FLOAT_SQUARE_ROOT:
            return from_float(math.sqrt(number) if number >= 0 else math.nan, input_width)
        case UnaryOpcode.FLOAT_IS_NAN:
            return int(math.isnan(number))
        case UnaryOpcode.FLOAT_CEILING:
            return from_float(_integral(number, math.ceil), input_width)
        case UnaryOpcode.FLOAT_FLOOR:
            return from_float(_integral(number, math.floor), input_width)
        case UnaryOpcode.FLOAT_ROUND:
            return from_float(_integral(number, lambda item: math.floor(item + 0.5)), input_width)
        case UnaryOpcode.FLOAT_TO_FLOAT:
            return from_float(number, output_width)
        case _:  # FLOAT_TO_SIGNED: p-code TRUNC rounds toward zero
            if math.isnan(number) or math.isinf(number):
                return 0
            return from_signed(int(number), output_width)


def _integral(number: float, rounding: Callable[[float], float | int]) -> float:
    """Rounding that leaves NaNs and infinities alone, as IEEE requires."""
    if math.isnan(number) or math.isinf(number):
        return number
    return float(rounding(number))


def binary(opcode: BinaryOpcode, left: int, right: int, width: int) -> int:
    """Evaluate a binary operation whose left operand is `width` bits wide.

    Shift amounts are unsigned and may have any width, so only the left width matters.
    """
    m = mask(width)
    match opcode:
        case (
            BinaryOpcode.FLOAT_ADD
            | BinaryOpcode.FLOAT_SUB
            | BinaryOpcode.FLOAT_MUL
            | BinaryOpcode.FLOAT_DIV
            | BinaryOpcode.FLOAT_EQUAL
            | BinaryOpcode.FLOAT_NOT_EQUAL
            | BinaryOpcode.FLOAT_LESS
            | BinaryOpcode.FLOAT_LESS_EQUAL
        ):
            return _float_binary(opcode, left, right, width)
        case BinaryOpcode.ADD | BinaryOpcode.POINTER_ADD:
            return (left + right) & m
        case BinaryOpcode.SUB | BinaryOpcode.POINTER_SUB:
            return (left - right) & m
        case BinaryOpcode.MUL:
            return (left * right) & m
        case BinaryOpcode.UNSIGNED_DIV:
            _require_divisor(right)
            return left // right
        case BinaryOpcode.UNSIGNED_REM:
            _require_divisor(right)
            return left % right
        case BinaryOpcode.SIGNED_DIV:
            _require_divisor(right)
            return from_signed(
                _truncating_div(to_signed(left, width), to_signed(right, width)), width
            )
        case BinaryOpcode.SIGNED_REM:
            _require_divisor(right)
            dividend = to_signed(left, width)
            divisor = to_signed(right, width)
            return from_signed(dividend - divisor * _truncating_div(dividend, divisor), width)
        case BinaryOpcode.AND | BinaryOpcode.BOOLEAN_AND:
            return left & right
        case BinaryOpcode.OR | BinaryOpcode.BOOLEAN_OR:
            return left | right
        case BinaryOpcode.XOR | BinaryOpcode.BOOLEAN_XOR:
            return left ^ right
        case BinaryOpcode.SHIFT_LEFT:
            return 0 if right >= width else (left << right) & m
        case BinaryOpcode.LOGICAL_SHIFT_RIGHT:
            return 0 if right >= width else left >> right
        case BinaryOpcode.ARITHMETIC_SHIFT_RIGHT:
            signed = to_signed(left, width)
            return from_signed(signed >> min(right, width), width)
        case BinaryOpcode.EQUAL:
            return int(left == right)
        case BinaryOpcode.NOT_EQUAL:
            return int(left != right)
        case BinaryOpcode.UNSIGNED_LESS:
            return int(left < right)
        case BinaryOpcode.UNSIGNED_LESS_EQUAL:
            return int(left <= right)
        case BinaryOpcode.SIGNED_LESS:
            return int(to_signed(left, width) < to_signed(right, width))
        case BinaryOpcode.SIGNED_LESS_EQUAL:
            return int(to_signed(left, width) <= to_signed(right, width))
        case BinaryOpcode.UNSIGNED_CARRY:
            return int(left + right > m)
        case BinaryOpcode.SIGNED_CARRY:
            return int(not _fits_signed(to_signed(left, width) + to_signed(right, width), width))
        case BinaryOpcode.SIGNED_BORROW:
            return int(not _fits_signed(to_signed(left, width) - to_signed(right, width), width))


def unary(opcode: UnaryOpcode, value: int, input_width: int, output_width: int) -> int:
    match opcode:
        case (
            UnaryOpcode.FLOAT_NEGATE
            | UnaryOpcode.FLOAT_ABSOLUTE
            | UnaryOpcode.FLOAT_SQUARE_ROOT
            | UnaryOpcode.FLOAT_IS_NAN
            | UnaryOpcode.FLOAT_CEILING
            | UnaryOpcode.FLOAT_FLOOR
            | UnaryOpcode.FLOAT_ROUND
            | UnaryOpcode.FLOAT_FROM_SIGNED
            | UnaryOpcode.FLOAT_TO_FLOAT
            | UnaryOpcode.FLOAT_TO_SIGNED
        ):
            return _float_unary(opcode, value, input_width, output_width)
        case UnaryOpcode.COPY | UnaryOpcode.ZERO_EXTEND:
            return value
        case UnaryOpcode.BITWISE_NOT:
            return value ^ mask(input_width)
        case UnaryOpcode.TWOS_COMPLEMENT:
            return -value & mask(input_width)
        case UnaryOpcode.BOOLEAN_NOT:
            return value ^ 1
        case UnaryOpcode.SIGN_EXTEND:
            return from_signed(to_signed(value, input_width), output_width)
        case UnaryOpcode.TRUNCATE:
            return value & mask(output_width)
        case UnaryOpcode.POPCOUNT:
            return value.bit_count() & mask(output_width)
        case UnaryOpcode.COUNT_LEADING_ZEROS:
            return (input_width - value.bit_length()) & mask(output_width)


def subpiece(value: int, low_bit: int, output_width: int) -> int:
    return (value >> low_bit) & mask(output_width)


def piece(high: int, low: int, low_width: int) -> int:
    return (high << low_width) | low


def _require_divisor(divisor: int) -> None:
    if divisor == 0:
        raise DivisionByZeroError("division by zero")


def _truncating_div(dividend: int, divisor: int) -> int:
    quotient = abs(dividend) // abs(divisor)
    return quotient if (dividend < 0) == (divisor < 0) else -quotient


def _fits_signed(value: int, width: int) -> bool:
    return -(1 << (width - 1)) <= value < (1 << (width - 1))

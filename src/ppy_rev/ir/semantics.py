"""Concrete semantics of RevIR operations on fixed-width values.

This is the reference definition every other consumer (the symbolic encoding, the PPy
emitter, simplification) is tested against. Values are Python integers in [0, 2**width).

Where p-code leaves behaviour open, RevIR decides explicitly:
- division and remainder by zero are faults (x86 raises #DE); callers must not continue;
- signed division overflow (MIN / -1) wraps to MIN, as Ghidra's emulator does;
- boolean operations act on whole bytes (`boolean_not x` is `x ^ 1`), as Ghidra's
  emulator does, which coincides with logical semantics on 0/1 inputs;
- shifts by at least the operand width yield 0 (or the sign fill for arithmetic shifts).
"""

from __future__ import annotations

from ppy_rev.ir.model import BinaryOpcode, UnaryOpcode, mask


class DivisionByZeroError(ArithmeticError):
    pass


def to_signed(value: int, width: int) -> int:
    sign = 1 << (width - 1)
    return (value ^ sign) - sign


def from_signed(value: int, width: int) -> int:
    return value & mask(width)


def binary(opcode: BinaryOpcode, left: int, right: int, width: int) -> int:
    """Evaluate a binary operation whose left operand is `width` bits wide.

    Shift amounts are unsigned and may have any width, so only the left width matters.
    """
    m = mask(width)
    match opcode:
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

"""Symbolic encodings of RevIR operations.

Each function mirrors the concrete definition in `ppy_rev.ir.semantics` exactly. Division
encodings assume a non-zero divisor; the executor constrains that separately, because a
zero divisor faults instead of producing a value.
"""

from __future__ import annotations

from ppy_rev.ir.model import BinaryOpcode, UnaryOpcode
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.expr import Expr


def _sign(value: Expr) -> Expr:
    return sx.extract(value, value.width - 1, 1)


def _flag_of(value: Expr) -> Expr | None:
    if value.op is sx.Op.ITE:
        condition, then, otherwise = value.args
        if then.is_const and otherwise.is_const and then.value == 1 and otherwise.value == 0:
            return condition
    return None


def binary(opcode: BinaryOpcode, left: Expr, right: Expr, output_width: int) -> Expr:
    match opcode:
        case BinaryOpcode.FLOAT_ADD:
            return sx.float_add(left, right)
        case BinaryOpcode.FLOAT_SUB:
            return sx.float_sub(left, right)
        case BinaryOpcode.FLOAT_MUL:
            return sx.float_mul(left, right)
        case BinaryOpcode.FLOAT_DIV:
            return sx.float_div(left, right)
        case BinaryOpcode.FLOAT_EQUAL:
            return sx.flag(sx.float_equal(left, right), output_width)
        case BinaryOpcode.FLOAT_NOT_EQUAL:
            return sx.flag(sx.bool_not(sx.float_equal(left, right)), output_width)
        case BinaryOpcode.FLOAT_LESS:
            return sx.flag(sx.float_less(left, right), output_width)
        case BinaryOpcode.FLOAT_LESS_EQUAL:
            return sx.flag(sx.float_less_equal(left, right), output_width)
        case BinaryOpcode.ADD | BinaryOpcode.POINTER_ADD:
            return sx.add(left, right)
        case BinaryOpcode.SUB | BinaryOpcode.POINTER_SUB:
            return sx.sub(left, right)
        case BinaryOpcode.MUL:
            return sx.mul(left, right)
        case BinaryOpcode.UNSIGNED_DIV:
            return sx.unsigned_div(left, right)
        case BinaryOpcode.SIGNED_DIV:
            return sx.signed_div(left, right)
        case BinaryOpcode.UNSIGNED_REM:
            return sx.unsigned_rem(left, right)
        case BinaryOpcode.SIGNED_REM:
            return sx.signed_rem(left, right)
        case BinaryOpcode.AND:
            return sx.bitwise_and(left, right)
        case BinaryOpcode.OR:
            return sx.bitwise_or(left, right)
        case BinaryOpcode.XOR:
            return sx.bitwise_xor(left, right)
        case BinaryOpcode.BOOLEAN_AND | BinaryOpcode.BOOLEAN_OR | BinaryOpcode.BOOLEAN_XOR:
            return _boolean(opcode, left, right)
        case BinaryOpcode.SHIFT_LEFT:
            return sx.shift_left(left, right)
        case BinaryOpcode.LOGICAL_SHIFT_RIGHT:
            return sx.logical_shift_right(left, right)
        case BinaryOpcode.ARITHMETIC_SHIFT_RIGHT:
            return sx.arithmetic_shift_right(left, right)
        case BinaryOpcode.EQUAL:
            return sx.flag(sx.equal(left, right), output_width)
        case BinaryOpcode.NOT_EQUAL:
            return sx.flag(sx.bool_not(sx.equal(left, right)), output_width)
        case BinaryOpcode.UNSIGNED_LESS:
            return sx.flag(sx.unsigned_less(left, right), output_width)
        case BinaryOpcode.UNSIGNED_LESS_EQUAL:
            return sx.flag(sx.unsigned_less_equal(left, right), output_width)
        case BinaryOpcode.SIGNED_LESS:
            return sx.flag(sx.signed_less(left, right), output_width)
        case BinaryOpcode.SIGNED_LESS_EQUAL:
            return sx.flag(sx.signed_less_equal(left, right), output_width)
        case BinaryOpcode.UNSIGNED_CARRY:
            return sx.flag(sx.unsigned_less(sx.add(left, right), left), output_width)
        case BinaryOpcode.SIGNED_CARRY:
            total = sx.add(left, right)
            same_signs = sx.equal(_sign(left), _sign(right))
            flipped = sx.bool_not(sx.equal(_sign(total), _sign(left)))
            return sx.flag(sx.bool_and(same_signs, flipped), output_width)
        case BinaryOpcode.SIGNED_BORROW:
            difference = sx.sub(left, right)
            different_signs = sx.bool_not(sx.equal(_sign(left), _sign(right)))
            flipped = sx.bool_not(sx.equal(_sign(difference), _sign(left)))
            return sx.flag(sx.bool_and(different_signs, flipped), output_width)


def _boolean(opcode: BinaryOpcode, left: Expr, right: Expr) -> Expr:
    """Bytewise, like Ghidra's emulator; stays boolean-structured for 0/1 flags."""
    left_flag, right_flag = _flag_of(left), _flag_of(right)
    if left_flag is not None and right_flag is not None:
        match opcode:
            case BinaryOpcode.BOOLEAN_AND:
                return sx.flag(sx.bool_and(left_flag, right_flag), left.width)
            case BinaryOpcode.BOOLEAN_OR:
                return sx.flag(sx.bool_or(left_flag, right_flag), left.width)
            case _:
                return sx.flag(sx.bool_xor(left_flag, right_flag), left.width)
    match opcode:
        case BinaryOpcode.BOOLEAN_AND:
            return sx.bitwise_and(left, right)
        case BinaryOpcode.BOOLEAN_OR:
            return sx.bitwise_or(left, right)
        case _:
            return sx.bitwise_xor(left, right)


def unary(opcode: UnaryOpcode, operand: Expr, output_width: int) -> Expr:
    match opcode:
        case UnaryOpcode.FLOAT_NEGATE:
            return sx.float_negate(operand)
        case UnaryOpcode.FLOAT_ABSOLUTE:
            return sx.float_absolute(operand)
        case UnaryOpcode.FLOAT_SQUARE_ROOT:
            return sx.float_square_root(operand)
        case UnaryOpcode.FLOAT_IS_NAN:
            return sx.flag(sx.float_is_nan(operand), output_width)
        case UnaryOpcode.FLOAT_CEILING:
            return sx.float_integral(operand, sx.Rounding.CEILING)
        case UnaryOpcode.FLOAT_FLOOR:
            return sx.float_integral(operand, sx.Rounding.FLOOR)
        case UnaryOpcode.FLOAT_ROUND:
            return sx.float_integral(operand, sx.Rounding.NEAREST)
        case UnaryOpcode.FLOAT_FROM_SIGNED:
            return sx.float_from_signed(operand, output_width)
        case UnaryOpcode.FLOAT_TO_FLOAT:
            return sx.float_to_float(operand, output_width)
        case UnaryOpcode.FLOAT_TO_SIGNED:
            return sx.float_to_signed(operand, output_width)
        case UnaryOpcode.COPY:
            return operand
        case UnaryOpcode.BITWISE_NOT:
            return sx.bitwise_not(operand)
        case UnaryOpcode.TWOS_COMPLEMENT:
            return sx.negate(operand)
        case UnaryOpcode.BOOLEAN_NOT:
            flag = _flag_of(operand)
            if flag is not None:
                return sx.flag(sx.bool_not(flag), operand.width)
            return sx.bitwise_xor(operand, sx.const(1, operand.width))
        case UnaryOpcode.ZERO_EXTEND:
            return sx.zero_extend(operand, output_width)
        case UnaryOpcode.SIGN_EXTEND:
            return sx.sign_extend(operand, output_width)
        case UnaryOpcode.TRUNCATE:
            return sx.extract(operand, 0, output_width)
        case UnaryOpcode.POPCOUNT:
            count = sx.const(0, output_width)
            for bit in range(operand.width):
                count = sx.add(count, _resize(sx.extract(operand, bit, 1), output_width))
            return count
        case UnaryOpcode.COUNT_LEADING_ZEROS:
            result = sx.const(operand.width, output_width)
            for bit in range(operand.width):
                is_set = sx.equal(sx.extract(operand, bit, 1), sx.const(1, 1))
                result = sx.ite(is_set, sx.const(operand.width - 1 - bit, output_width), result)
            return result


def _resize(value: Expr, width: int) -> Expr:
    if value.width == width:
        return value
    if value.width < width:
        return sx.zero_extend(value, width)
    return sx.extract(value, 0, width)


def subpiece(operand: Expr, low_bit: int, width: int) -> Expr:
    return sx.extract(operand, low_bit, width)


def piece(high: Expr, low: Expr) -> Expr:
    return sx.concat(high, low)

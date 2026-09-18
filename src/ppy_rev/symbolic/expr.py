"""Symbolic expressions over fixed-width bit vectors and booleans.

Expressions are immutable, hash-consed (structurally equal expressions are the same
object), and independent of any solver. Constructors fold constants with the reference
semantics in `ppy_rev.ir.semantics` and apply a small set of rewrites that are identities
for every operand value. Booleans are a separate sort (width 0) and never mix with bit
vectors implicitly.

Division and remainder by zero follow SMT-LIB here (so constant folding agrees with the
solver); the executor never builds such a division on a feasible path, because RevIR
faults instead.
"""

from __future__ import annotations

import weakref
from collections.abc import Iterator
from enum import IntEnum, StrEnum

from ppy_rev.ir import semantics
from ppy_rev.ir.model import FLOAT_WIDTHS, BinaryOpcode, UnaryOpcode, mask

BOOL = 0


class Op(StrEnum):
    CONST = "const"
    SYMBOL = "symbol"
    ADD = "bvadd"
    SUB = "bvsub"
    MUL = "bvmul"
    UDIV = "bvudiv"
    SDIV = "bvsdiv"
    UREM = "bvurem"
    SREM = "bvsrem"
    AND = "bvand"
    OR = "bvor"
    XOR = "bvxor"
    NOT = "bvnot"
    NEG = "bvneg"
    SHL = "bvshl"
    LSHR = "bvlshr"
    ASHR = "bvashr"
    CONCAT = "concat"
    EXTRACT = "extract"
    ZERO_EXTEND = "zero_extend"
    SIGN_EXTEND = "sign_extend"
    ITE = "ite"
    EQ = "="
    ULT = "bvult"
    ULE = "bvule"
    SLT = "bvslt"
    SLE = "bvsle"
    BOOL_AND = "and"
    BOOL_OR = "or"
    BOOL_NOT = "not"
    BOOL_XOR = "xor"
    FLOAT_ADD = "fp.add"
    FLOAT_SUB = "fp.sub"
    FLOAT_MUL = "fp.mul"
    FLOAT_DIV = "fp.div"
    FLOAT_NEG = "fp.neg"
    FLOAT_ABS = "fp.abs"
    FLOAT_SQRT = "fp.sqrt"
    FLOAT_INTEGRAL = "fp.roundToIntegral"
    FLOAT_EQ = "fp.eq"
    FLOAT_LT = "fp.lt"
    FLOAT_LE = "fp.leq"
    FLOAT_IS_NAN = "fp.isNaN"
    FLOAT_FROM_SIGNED = "fp.from_sbv"
    FLOAT_TO_FLOAT = "fp.to_fp"
    FLOAT_TO_SIGNED = "fp.to_sbv"


class Rounding(IntEnum):
    """How `fp.roundToIntegral` rounds, matching p-code's CEIL, FLOOR and ROUND."""

    CEILING = 0
    FLOOR = 1
    NEAREST = 2


type _Key = tuple[Op, int, tuple[Expr, ...], int, str]
_TABLE: weakref.WeakValueDictionary[_Key, Expr] = weakref.WeakValueDictionary()


class Expr:
    """A hash-consed expression node. Compare with `is`; equality is identity."""

    __slots__ = ("__weakref__", "args", "name", "op", "value", "width")

    op: Op
    width: int
    args: tuple[Expr, ...]
    value: int
    """Constant value, extract low bit, or extension amount; 0 otherwise."""
    name: str

    def __init__(self, op: Op, width: int, args: tuple[Expr, ...], value: int, name: str) -> None:
        self.op = op
        self.width = width
        self.args = args
        self.value = value
        self.name = name

    @property
    def is_bool(self) -> bool:
        return self.width == BOOL

    @property
    def is_const(self) -> bool:
        return self.op is Op.CONST

    def __repr__(self) -> str:
        return render(self)


def _make(op: Op, width: int, args: tuple[Expr, ...] = (), value: int = 0, name: str = "") -> Expr:
    key: _Key = (op, width, args, value, name)
    existing = _TABLE.get(key)
    if existing is not None:
        return existing
    created = Expr(op, width, args, value, name)
    _TABLE[key] = created
    return created


# -- leaves ------------------------------------------------------------------------------


def const(value: int, width: int) -> Expr:
    if width <= 0:
        raise ValueError("bit-vector constants need a positive width")
    return _make(Op.CONST, width, value=value & mask(width))


def boolean(value: bool) -> Expr:
    return _make(Op.CONST, BOOL, value=int(value))


TRUE = boolean(True)
FALSE = boolean(False)


def symbol(name: str, width: int) -> Expr:
    return _make(Op.SYMBOL, width, name=name)


def _same_width(*operands: Expr) -> int:
    width = operands[0].width
    if width == BOOL or any(operand.width != width for operand in operands):
        raise ValueError(f"operand widths differ: {[operand.width for operand in operands]}")
    return width


def _fold(opcode: BinaryOpcode, left: Expr, right: Expr) -> Expr:
    return const(semantics.binary(opcode, left.value, right.value, left.width), left.width)


# -- arithmetic --------------------------------------------------------------------------


def add(left: Expr, right: Expr) -> Expr:
    width = _same_width(left, right)
    if left.is_const and not right.is_const:
        left, right = right, left
    if right.is_const:
        if left.is_const:
            return _fold(BinaryOpcode.ADD, left, right)
        if right.value == 0:
            return left
        if left.op is Op.ADD and left.args[1].is_const:
            return add(left.args[0], const(left.args[1].value + right.value, width))
    return _make(Op.ADD, width, (left, right))


def sub(left: Expr, right: Expr) -> Expr:
    width = _same_width(left, right)
    if left is right:
        return const(0, width)
    if right.is_const:
        return add(left, const(-right.value, width))
    return _make(Op.SUB, width, (left, right))


def mul(left: Expr, right: Expr) -> Expr:
    width = _same_width(left, right)
    if left.is_const and not right.is_const:
        left, right = right, left
    if right.is_const:
        if left.is_const:
            return _fold(BinaryOpcode.MUL, left, right)
        if right.value == 0:
            return right
        if right.value == 1:
            return left
    return _make(Op.MUL, width, (left, right))


def _smt_division(op: Op, left: Expr, right: Expr) -> Expr:
    width = _same_width(left, right)
    if left.is_const and right.is_const:
        if right.value == 0:
            return const(_smt_division_by_zero(op, left.value, width), width)
        opcode = {
            Op.UDIV: BinaryOpcode.UNSIGNED_DIV,
            Op.SDIV: BinaryOpcode.SIGNED_DIV,
            Op.UREM: BinaryOpcode.UNSIGNED_REM,
            Op.SREM: BinaryOpcode.SIGNED_REM,
        }[op]
        return _fold(opcode, left, right)
    if right.is_const and right.value == 1:
        return left if op in (Op.UDIV, Op.SDIV) else const(0, width)
    return _make(op, width, (left, right))


def _smt_division_by_zero(op: Op, dividend: int, width: int) -> int:
    match op:
        case Op.UDIV:
            return mask(width)
        case Op.SDIV:
            return 1 if semantics.to_signed(dividend, width) < 0 else mask(width)
        case _:
            return dividend


def unsigned_div(left: Expr, right: Expr) -> Expr:
    return _smt_division(Op.UDIV, left, right)


def signed_div(left: Expr, right: Expr) -> Expr:
    return _smt_division(Op.SDIV, left, right)


def unsigned_rem(left: Expr, right: Expr) -> Expr:
    return _smt_division(Op.UREM, left, right)


def signed_rem(left: Expr, right: Expr) -> Expr:
    return _smt_division(Op.SREM, left, right)


def negate(operand: Expr) -> Expr:
    width = _same_width(operand)
    if operand.is_const:
        return const(-operand.value, width)
    if operand.op is Op.NEG:
        return operand.args[0]
    return _make(Op.NEG, width, (operand,))


# -- bitwise -----------------------------------------------------------------------------


def bitwise_and(left: Expr, right: Expr) -> Expr:
    width = _same_width(left, right)
    if left is right:
        return left
    if left.is_const and not right.is_const:
        left, right = right, left
    if right.is_const:
        if left.is_const:
            return const(left.value & right.value, width)
        if right.value == 0:
            return right
        if right.value == mask(width):
            return left
        if left.op is Op.AND and left.args[1].is_const:
            return bitwise_and(left.args[0], const(left.args[1].value & right.value, width))
    return _make(Op.AND, width, (left, right))


def bitwise_or(left: Expr, right: Expr) -> Expr:
    width = _same_width(left, right)
    if left is right:
        return left
    if left.is_const and not right.is_const:
        left, right = right, left
    if right.is_const:
        if left.is_const:
            return const(left.value | right.value, width)
        if right.value == 0:
            return left
        if right.value == mask(width):
            return right
    return _make(Op.OR, width, (left, right))


def bitwise_xor(left: Expr, right: Expr) -> Expr:
    width = _same_width(left, right)
    if left is right:
        return const(0, width)
    if left.is_const and not right.is_const:
        left, right = right, left
    if right.is_const:
        if left.is_const:
            return const(left.value ^ right.value, width)
        if right.value == 0:
            return left
        if left.op is Op.XOR and left.args[1].is_const:
            return bitwise_xor(left.args[0], const(left.args[1].value ^ right.value, width))
    return _make(Op.XOR, width, (left, right))


def bitwise_not(operand: Expr) -> Expr:
    width = _same_width(operand)
    if operand.is_const:
        return const(~operand.value, width)
    if operand.op is Op.NOT:
        return operand.args[0]
    return _make(Op.NOT, width, (operand,))


def _shift_amount(amount: Expr, width: int) -> Expr | None:
    """The amount as a `width`-bit value, or None when it is at least `width` for sure."""
    if amount.width == width:
        return amount
    if amount.width < width:
        return zero_extend(amount, width)
    if amount.is_const:
        return None if amount.value >= width else const(amount.value, width)
    return None


def _shift(op: Op, value: Expr, amount: Expr) -> Expr:
    width = _same_width(value)
    if amount.is_bool:
        raise ValueError("shift amounts are bit vectors")
    normalized = _shift_amount(amount, width)
    if normalized is None and amount.is_const:
        # Shifting by at least the width: zero, or the sign fill for arithmetic shifts.
        if op is Op.ASHR:
            return _make_shift(Op.ASHR, value, const(width - 1, width))
        return const(0, width)
    if normalized is None:
        # A wider symbolic amount: shifts of `width` or more saturate.
        in_range = unsigned_less(amount, const(width, amount.width))
        narrowed = extract(amount, 0, width)
        saturated = (
            _make_shift(Op.ASHR, value, const(width - 1, width))
            if op is Op.ASHR
            else const(0, width)
        )
        return ite(in_range, _make_shift(op, value, narrowed), saturated)
    return _make_shift(op, value, normalized)


def _make_shift(op: Op, value: Expr, amount: Expr) -> Expr:
    width = value.width
    if amount.is_const:
        if amount.value == 0:
            return value
        if value.is_const:
            opcode = {
                Op.SHL: BinaryOpcode.SHIFT_LEFT,
                Op.LSHR: BinaryOpcode.LOGICAL_SHIFT_RIGHT,
                Op.ASHR: BinaryOpcode.ARITHMETIC_SHIFT_RIGHT,
            }[op]
            return const(semantics.binary(opcode, value.value, amount.value, width), width)
    return _make(op, width, (value, amount))


def shift_left(value: Expr, amount: Expr) -> Expr:
    return _shift(Op.SHL, value, amount)


def logical_shift_right(value: Expr, amount: Expr) -> Expr:
    return _shift(Op.LSHR, value, amount)


def arithmetic_shift_right(value: Expr, amount: Expr) -> Expr:
    return _shift(Op.ASHR, value, amount)


# -- width changes -----------------------------------------------------------------------


def concat(high: Expr, low: Expr) -> Expr:
    if high.is_bool or low.is_bool:
        raise ValueError("concat operates on bit vectors")
    width = high.width + low.width
    if high.is_const and low.is_const:
        return const((high.value << low.width) | low.value, width)
    if high.is_const and high.value == 0:
        return zero_extend(low, width)
    if (
        high.op is Op.EXTRACT
        and low.op is Op.EXTRACT
        and high.args[0] is low.args[0]
        and high.value == low.value + low.width
    ):
        return extract(high.args[0], low.value, width)
    return _make(Op.CONCAT, width, (high, low))


def extract(operand: Expr, low_bit: int, width: int) -> Expr:
    """`width` bits of `operand` starting at `low_bit` (must lie within the operand)."""
    if operand.is_bool or low_bit < 0 or low_bit + width > operand.width or width <= 0:
        raise ValueError(f"cannot extract {width} bits at {low_bit} from {operand.width} bits")
    if low_bit == 0 and width == operand.width:
        return operand
    if operand.is_const:
        return const(operand.value >> low_bit, width)
    match operand.op:
        case Op.EXTRACT:
            return extract(operand.args[0], operand.value + low_bit, width)
        case Op.CONCAT:
            high, low = operand.args
            if low_bit >= low.width:
                return extract(high, low_bit - low.width, width)
            if low_bit + width <= low.width:
                return extract(low, low_bit, width)
        case Op.ZERO_EXTEND:
            source = operand.args[0]
            if low_bit >= source.width:
                return const(0, width)
            if low_bit + width <= source.width:
                return extract(source, low_bit, width)
        case Op.SIGN_EXTEND:
            source = operand.args[0]
            if low_bit + width <= source.width:
                return extract(source, low_bit, width)
        case Op.AND | Op.OR | Op.XOR if low_bit == 0:
            left, right = operand.args
            if left.is_const or right.is_const:
                builder = {Op.AND: bitwise_and, Op.OR: bitwise_or, Op.XOR: bitwise_xor}[operand.op]
                return builder(extract(left, 0, width), extract(right, 0, width))
        case Op.ITE:
            condition, then, otherwise = operand.args
            if then.is_const and otherwise.is_const:
                return ite(
                    condition, extract(then, low_bit, width), extract(otherwise, low_bit, width)
                )
        case _:
            pass
    return _make(Op.EXTRACT, width, (operand,), value=low_bit)


def zero_extend(operand: Expr, width: int) -> Expr:
    if operand.is_bool or width < operand.width:
        raise ValueError("zero_extend must not narrow")
    if width == operand.width:
        return operand
    if operand.is_const:
        return const(operand.value, width)
    if operand.op is Op.ZERO_EXTEND:
        return zero_extend(operand.args[0], width)
    return _make(Op.ZERO_EXTEND, width, (operand,), value=width - operand.width)


def sign_extend(operand: Expr, width: int) -> Expr:
    if operand.is_bool or width < operand.width:
        raise ValueError("sign_extend must not narrow")
    if width == operand.width:
        return operand
    if operand.is_const:
        return const(semantics.to_signed(operand.value, operand.width), width)
    if operand.op is Op.SIGN_EXTEND:
        return sign_extend(operand.args[0], width)
    return _make(Op.SIGN_EXTEND, width, (operand,), value=width - operand.width)


def ite(condition: Expr, then: Expr, otherwise: Expr) -> Expr:
    if not condition.is_bool or then.width != otherwise.width:
        raise ValueError("ite needs a boolean condition and branches of equal sort")
    if condition.is_const:
        return then if condition.value else otherwise
    if then is otherwise:
        return then
    if condition.op is Op.BOOL_NOT:
        return ite(condition.args[0], otherwise, then)
    if then.is_bool:
        if then is TRUE and otherwise is FALSE:
            return condition
        if then is FALSE and otherwise is TRUE:
            return bool_not(condition)
    return _make(Op.ITE, then.width, (condition, then, otherwise))


# -- comparisons and booleans ------------------------------------------------------------


def equal(left: Expr, right: Expr) -> Expr:
    _same_width(left, right)
    if left is right:
        return TRUE
    if left.is_const and not right.is_const:
        left, right = right, left
    if right.is_const:
        if left.is_const:
            return boolean(left.value == right.value)
        flag = _flag_of(left)
        if flag is not None:
            return flag if right.value == 1 else FALSE if right.value != 0 else bool_not(flag)
        inverted = _invert_equality(left, right.value)
        if inverted is not None:
            return inverted
    return _make(Op.EQ, BOOL, (left, right))


def _invert_equality(left: Expr, value: int) -> Expr | None:
    """`left == value` for an invertible `left`, as an equality on its operand.

    Each rewrite is exact under bit-vector semantics; the solver then sees the input byte
    compared with a constant instead of a computation over it.
    """
    width = left.width
    match left.op:
        case Op.XOR if left.args[1].is_const:
            return equal(left.args[0], const(left.args[1].value ^ value, width))
        case Op.ADD if left.args[1].is_const:
            return equal(left.args[0], const(value - left.args[1].value, width))
        case Op.MUL if left.args[1].is_const and left.args[1].value & 1:
            inverse = pow(left.args[1].value, -1, 1 << width)
            return equal(left.args[0], const(value * inverse, width))
        case Op.NOT:
            return equal(left.args[0], const(~value, width))
        case Op.NEG:
            return equal(left.args[0], const(-value, width))
        case Op.ZERO_EXTEND:
            inner = left.args[0]
            if value >> inner.width:
                return FALSE
            return equal(inner, const(value, inner.width))
        case Op.SIGN_EXTEND:
            inner = left.args[0]
            low = value & mask(inner.width)
            if const(semantics.to_signed(low, inner.width), width).value != value:
                return FALSE
            return equal(inner, const(low, inner.width))
        case Op.CONCAT:
            high, low = left.args
            return bool_and(
                equal(high, const(value >> low.width, high.width)),
                equal(low, const(value, low.width)),
            )
        case _:
            return None


def _flag_of(operand: Expr) -> Expr | None:
    """For `ite(b, 1, 0)`, the boolean `b`."""
    if operand.op is Op.ITE:
        condition, then, otherwise = operand.args
        if then.is_const and otherwise.is_const and then.value == 1 and otherwise.value == 0:
            return condition
    return None


def _comparison(op: Op, left: Expr, right: Expr) -> Expr:
    width = _same_width(left, right)
    if left.is_const and right.is_const:
        opcode = {
            Op.ULT: BinaryOpcode.UNSIGNED_LESS,
            Op.ULE: BinaryOpcode.UNSIGNED_LESS_EQUAL,
            Op.SLT: BinaryOpcode.SIGNED_LESS,
            Op.SLE: BinaryOpcode.SIGNED_LESS_EQUAL,
        }[op]
        return boolean(bool(semantics.binary(opcode, left.value, right.value, width)))
    if left is right:
        return boolean(op in (Op.ULE, Op.SLE))
    if op is Op.ULT and right.is_const and right.value == 0:
        return FALSE
    if op is Op.ULE and left.is_const and left.value == 0:
        return TRUE
    return _make(op, BOOL, (left, right))


def unsigned_less(left: Expr, right: Expr) -> Expr:
    return _comparison(Op.ULT, left, right)


def unsigned_less_equal(left: Expr, right: Expr) -> Expr:
    return _comparison(Op.ULE, left, right)


def signed_less(left: Expr, right: Expr) -> Expr:
    return _comparison(Op.SLT, left, right)


def signed_less_equal(left: Expr, right: Expr) -> Expr:
    return _comparison(Op.SLE, left, right)


def _require_bool(*operands: Expr) -> None:
    if any(not operand.is_bool for operand in operands):
        raise ValueError("boolean operation on a bit vector")


def bool_not(operand: Expr) -> Expr:
    _require_bool(operand)
    if operand.is_const:
        return boolean(not operand.value)
    if operand.op is Op.BOOL_NOT:
        return operand.args[0]
    return _make(Op.BOOL_NOT, BOOL, (operand,))


def bool_and(*operands: Expr) -> Expr:
    _require_bool(*operands)
    flattened: list[Expr] = []
    seen: set[int] = set()
    for operand in operands:
        if operand is FALSE:
            return FALSE
        if operand is TRUE:
            continue
        for part in operand.args if operand.op is Op.BOOL_AND else (operand,):
            if id(part) not in seen:
                seen.add(id(part))
                flattened.append(part)
    if not flattened:
        return TRUE
    if len(flattened) == 1:
        return flattened[0]
    return _make(Op.BOOL_AND, BOOL, tuple(flattened))


def bool_or(*operands: Expr) -> Expr:
    _require_bool(*operands)
    flattened: list[Expr] = []
    seen: set[int] = set()
    for operand in operands:
        if operand is TRUE:
            return TRUE
        if operand is FALSE:
            continue
        for part in operand.args if operand.op is Op.BOOL_OR else (operand,):
            if id(part) not in seen:
                seen.add(id(part))
                flattened.append(part)
    if not flattened:
        return FALSE
    if len(flattened) == 1:
        return flattened[0]
    return _make(Op.BOOL_OR, BOOL, tuple(flattened))


def bool_xor(left: Expr, right: Expr) -> Expr:
    _require_bool(left, right)
    if left.is_const and right.is_const:
        return boolean(left.value != right.value)
    if left is right:
        return FALSE
    if left.is_const:
        left, right = right, left
    if right.is_const:
        return bool_not(left) if right.value else left
    return _make(Op.BOOL_XOR, BOOL, (left, right))


# -- conversions between p-code bytes and booleans ---------------------------------------


def flag(condition: Expr, width: int = 8) -> Expr:
    """A p-code boolean: `width` bits holding 1 when `condition` holds, else 0."""
    return ite(condition, const(1, width), const(0, width))


def nonzero(value: Expr) -> Expr:
    return bool_not(equal(value, const(0, value.width)))


def walk(root: Expr) -> Iterator[Expr]:
    """Every distinct node reachable from `root`, children before parents."""
    seen: set[int] = set()
    stack: list[tuple[Expr, bool]] = [(root, False)]
    while stack:
        node, expanded = stack.pop()
        if id(node) in seen:
            continue
        if expanded:
            seen.add(id(node))
            yield node
            continue
        stack.append((node, True))
        stack.extend((child, False) for child in reversed(node.args) if id(child) not in seen)


def symbols(root: Expr) -> list[Expr]:
    return [node for node in walk(root) if node.op is Op.SYMBOL]


def render(root: Expr, limit: int = 400) -> str:
    """A readable, bounded rendering for diagnostics and reports."""
    text = _render(root, limit)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _render(node: Expr, budget: int) -> str:
    match node.op:
        case Op.CONST:
            if node.is_bool:
                return "true" if node.value else "false"
            return f"{node.value:#x}:{node.width}"
        case Op.SYMBOL:
            return node.name
        case Op.EXTRACT:
            return f"{_render(node.args[0], budget)}[{node.value}:{node.value + node.width}]"
        case Op.ZERO_EXTEND | Op.SIGN_EXTEND:
            return f"{node.op}{node.width}({_render(node.args[0], budget)})"
        case _:
            if budget <= 0:
                return "..."
            inner = ", ".join(
                _render(child, budget // max(1, len(node.args))) for child in node.args
            )
            return f"{node.op}({inner})"


# -- floating point ----------------------------------------------------------------------
#
# IEEE-754 numbers travel as their bit patterns, so registers, memory and every other part
# of the system stay bit vectors; only these operations read them as numbers.


def _float_width(*operands: Expr) -> int:
    width = _same_width(*operands)
    if width not in FLOAT_WIDTHS:
        raise ValueError(f"{width}-bit floating point is not modeled")
    return width


def _fold_binary(opcode: BinaryOpcode, left: Expr, right: Expr, width: int) -> Expr | None:
    if not (left.is_const and right.is_const):
        return None
    value = semantics.binary(opcode, left.value, right.value, left.width)
    return boolean(bool(value)) if width == BOOL else const(value, width)


def _fold_unary(opcode: UnaryOpcode, operand: Expr, width: int) -> Expr | None:
    if not operand.is_const:
        return None
    value = semantics.unary(opcode, operand.value, operand.width, max(width, 1))
    return boolean(bool(value)) if width == BOOL else const(value, width)


def float_add(left: Expr, right: Expr) -> Expr:
    width = _float_width(left, right)
    folded = _fold_binary(BinaryOpcode.FLOAT_ADD, left, right, width)
    return folded if folded is not None else _make(Op.FLOAT_ADD, width, (left, right))


def float_sub(left: Expr, right: Expr) -> Expr:
    width = _float_width(left, right)
    folded = _fold_binary(BinaryOpcode.FLOAT_SUB, left, right, width)
    return folded if folded is not None else _make(Op.FLOAT_SUB, width, (left, right))


def float_mul(left: Expr, right: Expr) -> Expr:
    width = _float_width(left, right)
    folded = _fold_binary(BinaryOpcode.FLOAT_MUL, left, right, width)
    return folded if folded is not None else _make(Op.FLOAT_MUL, width, (left, right))


def float_div(left: Expr, right: Expr) -> Expr:
    width = _float_width(left, right)
    folded = _fold_binary(BinaryOpcode.FLOAT_DIV, left, right, width)
    return folded if folded is not None else _make(Op.FLOAT_DIV, width, (left, right))


def float_negate(operand: Expr) -> Expr:
    width = _float_width(operand)
    folded = _fold_unary(UnaryOpcode.FLOAT_NEGATE, operand, width)
    return folded if folded is not None else _make(Op.FLOAT_NEG, width, (operand,))


def float_absolute(operand: Expr) -> Expr:
    width = _float_width(operand)
    folded = _fold_unary(UnaryOpcode.FLOAT_ABSOLUTE, operand, width)
    return folded if folded is not None else _make(Op.FLOAT_ABS, width, (operand,))


def float_square_root(operand: Expr) -> Expr:
    width = _float_width(operand)
    folded = _fold_unary(UnaryOpcode.FLOAT_SQUARE_ROOT, operand, width)
    return folded if folded is not None else _make(Op.FLOAT_SQRT, width, (operand,))


_INTEGRAL_OPCODES = {
    Rounding.CEILING: UnaryOpcode.FLOAT_CEILING,
    Rounding.FLOOR: UnaryOpcode.FLOAT_FLOOR,
    Rounding.NEAREST: UnaryOpcode.FLOAT_ROUND,
}


def float_integral(operand: Expr, rounding: Rounding) -> Expr:
    width = _float_width(operand)
    folded = _fold_unary(_INTEGRAL_OPCODES[rounding], operand, width)
    if folded is not None:
        return folded
    return _make(Op.FLOAT_INTEGRAL, width, (operand,), value=int(rounding))


def float_equal(left: Expr, right: Expr) -> Expr:
    _float_width(left, right)
    folded = _fold_binary(BinaryOpcode.FLOAT_EQUAL, left, right, BOOL)
    return folded if folded is not None else _make(Op.FLOAT_EQ, BOOL, (left, right))


def float_less(left: Expr, right: Expr) -> Expr:
    _float_width(left, right)
    folded = _fold_binary(BinaryOpcode.FLOAT_LESS, left, right, BOOL)
    return folded if folded is not None else _make(Op.FLOAT_LT, BOOL, (left, right))


def float_less_equal(left: Expr, right: Expr) -> Expr:
    _float_width(left, right)
    folded = _fold_binary(BinaryOpcode.FLOAT_LESS_EQUAL, left, right, BOOL)
    return folded if folded is not None else _make(Op.FLOAT_LE, BOOL, (left, right))


def float_is_nan(operand: Expr) -> Expr:
    _float_width(operand)
    folded = _fold_unary(UnaryOpcode.FLOAT_IS_NAN, operand, BOOL)
    return folded if folded is not None else _make(Op.FLOAT_IS_NAN, BOOL, (operand,))


def float_from_signed(operand: Expr, width: int) -> Expr:
    """A signed integer as an IEEE-754 number of `width` bits."""
    if width not in FLOAT_WIDTHS:
        raise ValueError(f"{width}-bit floating point is not modeled")
    folded = _fold_unary(UnaryOpcode.FLOAT_FROM_SIGNED, operand, width)
    return folded if folded is not None else _make(Op.FLOAT_FROM_SIGNED, width, (operand,))


def float_to_float(operand: Expr, width: int) -> Expr:
    _float_width(operand)
    if width not in FLOAT_WIDTHS:
        raise ValueError(f"{width}-bit floating point is not modeled")
    if width == operand.width:
        return operand
    folded = _fold_unary(UnaryOpcode.FLOAT_TO_FLOAT, operand, width)
    return folded if folded is not None else _make(Op.FLOAT_TO_FLOAT, width, (operand,))


def float_to_signed(operand: Expr, width: int) -> Expr:
    """An IEEE-754 number truncated toward zero into a `width`-bit signed integer."""
    _float_width(operand)
    folded = _fold_unary(UnaryOpcode.FLOAT_TO_SIGNED, operand, width)
    return folded if folded is not None else _make(Op.FLOAT_TO_SIGNED, width, (operand,))

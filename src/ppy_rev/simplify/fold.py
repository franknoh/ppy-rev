"""Constant folding, width-exact algebraic identities, and phi simplification.

Every rewrite here is an identity on fixed-width bit vectors for all operand values;
folding reuses `ppy_rev.ir.semantics`, so a folded constant is exactly what execution
would compute. Operations that can fault are never folded away.
"""

from __future__ import annotations

from dataclasses import replace

from ppy_rev.ir import semantics
from ppy_rev.ir.cfg import control_flow
from ppy_rev.ir.model import (
    DIVISION_OPCODES,
    BinaryOp,
    BinaryOpcode,
    Const,
    Function,
    Operand,
    Operation,
    Piece,
    Subpiece,
    UnaryOp,
    UnaryOpcode,
    Var,
    mask,
    operation_output,
)
from ppy_rev.ir.transform import map_operation, resolver, substitute

type Definitions = dict[int, Operation]
_ITERATION_LIMIT = 50


def fold_function(function: Function) -> Function:
    for _ in range(_ITERATION_LIMIT):
        folded = _fold_once(function)
        if folded == function:
            return function
        function = folded
    return function


def _fold_once(function: Function) -> Function:
    replacements: dict[int, Operand] = {}
    use = resolver(replacements)
    definitions: Definitions = {}
    blocks = {block.id: block for block in function.blocks}
    rewritten = dict(blocks)
    for block_id in control_flow(function).reverse_postorder:
        block = blocks[block_id]
        for phi in block.phis:
            distinct = {use(value) for _, value in phi.incoming} - {phi.output}
            if len(distinct) == 1:
                replacements[phi.output.id] = distinct.pop()
        operations: list[Operation] = []
        for operation in block.operations:
            current = map_operation(operation, use)
            result = simplify_operation(current, definitions)
            if isinstance(result, Var | Const):
                (output,) = operation_output(current)
                replacements[output.id] = result
                operations.append(current)
                continue
            if isinstance(result, BinaryOp | UnaryOp | Subpiece | Piece):
                definitions[result.output.id] = result
            operations.append(result)
        rewritten[block_id] = replace(block, operations=tuple(operations))
    return substitute(
        replace(function, blocks=tuple(rewritten[block.id] for block in function.blocks)),
        replacements,
    )


def simplify_operation(operation: Operation, definitions: Definitions) -> Operation | Operand:
    """Return a replacement operand, a simpler operation, or the operation unchanged."""
    match operation:
        case BinaryOp():
            return _binary(operation, definitions)
        case UnaryOp():
            return _unary(operation, definitions)
        case Subpiece():
            return _subpiece(operation, definitions)
        case Piece():
            return _piece(operation, definitions)
        case _:
            return operation


def _const(value: int, width: int) -> Const:
    return Const(value & mask(width), width)


def _binary(op: BinaryOp, definitions: Definitions) -> Operation | Operand:
    opcode, left, right, width = op.opcode, op.left, op.right, op.output.width
    if isinstance(left, Const) and isinstance(right, Const):
        if opcode in DIVISION_OPCODES and right.value == 0:
            return op
        return _const(semantics.binary(opcode, left.value, right.value, left.width), width)
    zero = isinstance(right, Const) and right.value == 0
    one = isinstance(right, Const) and right.value == 1
    full = isinstance(right, Const) and right.value == mask(right.width)
    same = left == right
    match opcode:
        case BinaryOpcode.ADD | BinaryOpcode.SUB | BinaryOpcode.OR | BinaryOpcode.XOR if zero:
            return left
        case BinaryOpcode.SHIFT_LEFT | BinaryOpcode.LOGICAL_SHIFT_RIGHT if zero:
            return left
        case BinaryOpcode.ARITHMETIC_SHIFT_RIGHT if zero:
            return left
        case BinaryOpcode.SUB | BinaryOpcode.XOR if same:
            return _const(0, width)
        case BinaryOpcode.AND | BinaryOpcode.OR if same:
            return left
        case BinaryOpcode.AND if zero:
            return _const(0, width)
        case BinaryOpcode.AND if full:
            return left
        case BinaryOpcode.OR if full:
            return _const(mask(width), width)
        case BinaryOpcode.MUL if one:
            return left
        case BinaryOpcode.MUL if zero:
            return _const(0, width)
        case BinaryOpcode.UNSIGNED_DIV | BinaryOpcode.SIGNED_DIV if one:
            return left
        case BinaryOpcode.UNSIGNED_REM if one:
            return _const(0, width)
        case BinaryOpcode.EQUAL | BinaryOpcode.UNSIGNED_LESS_EQUAL if same:
            return _const(1, width)
        case BinaryOpcode.SIGNED_LESS_EQUAL if same:
            return _const(1, width)
        case BinaryOpcode.NOT_EQUAL | BinaryOpcode.UNSIGNED_LESS | BinaryOpcode.SIGNED_LESS if same:
            return _const(0, width)
        case BinaryOpcode.UNSIGNED_CARRY | BinaryOpcode.SIGNED_CARRY if zero:
            return _const(0, width)
        case BinaryOpcode.SIGNED_BORROW if zero:
            return _const(0, width)
        case BinaryOpcode.UNSIGNED_LESS if zero:
            return _const(0, width)
        case _:
            pass
    if isinstance(left, Const) and not isinstance(right, Const) and _commutative(opcode):
        return replace(op, left=right, right=left)
    return _combine_constants(op, definitions)


def _commutative(opcode: BinaryOpcode) -> bool:
    return opcode in {
        BinaryOpcode.ADD,
        BinaryOpcode.MUL,
        BinaryOpcode.AND,
        BinaryOpcode.OR,
        BinaryOpcode.XOR,
        BinaryOpcode.EQUAL,
        BinaryOpcode.NOT_EQUAL,
        BinaryOpcode.UNSIGNED_CARRY,
        BinaryOpcode.SIGNED_CARRY,
        BinaryOpcode.BOOLEAN_AND,
        BinaryOpcode.BOOLEAN_OR,
        BinaryOpcode.BOOLEAN_XOR,
    }


def _combine_constants(op: BinaryOp, definitions: Definitions) -> Operation | Operand:
    """(x op c1) op c2 → x op (c1 op c2) for associative ops; add/sub chains merge."""
    if not isinstance(op.right, Const) or not isinstance(op.left, Var):
        return op
    inner = definitions.get(op.left.id)
    if not isinstance(inner, BinaryOp) or not isinstance(inner.right, Const):
        return op
    width = op.output.width
    if op.opcode in (BinaryOpcode.ADD, BinaryOpcode.SUB) and inner.opcode in (
        BinaryOpcode.ADD,
        BinaryOpcode.SUB,
    ):
        inner_offset = inner.right.value if inner.opcode is BinaryOpcode.ADD else -inner.right.value
        outer_offset = op.right.value if op.opcode is BinaryOpcode.ADD else -op.right.value
        total = (inner_offset + outer_offset) & mask(width)
        if total == 0:
            return inner.left
        return replace(op, opcode=BinaryOpcode.ADD, left=inner.left, right=_const(total, width))
    if op.opcode is inner.opcode and op.opcode in (
        BinaryOpcode.AND,
        BinaryOpcode.OR,
        BinaryOpcode.XOR,
        BinaryOpcode.MUL,
    ):
        combined = semantics.binary(op.opcode, inner.right.value, op.right.value, width)
        return replace(op, left=inner.left, right=_const(combined, width))
    return op


def _unary(op: UnaryOp, definitions: Definitions) -> Operation | Operand:
    operand = op.operand
    if isinstance(operand, Const):
        return _const(
            semantics.unary(op.opcode, operand.value, operand.width, op.output.width),
            op.output.width,
        )
    if op.opcode is UnaryOpcode.COPY:
        return operand
    inner = definitions.get(operand.id)
    match op.opcode, inner:
        case UnaryOpcode.BITWISE_NOT, UnaryOp(opcode=UnaryOpcode.BITWISE_NOT):
            return inner.operand
        case UnaryOpcode.TWOS_COMPLEMENT, UnaryOp(opcode=UnaryOpcode.TWOS_COMPLEMENT):
            return inner.operand
        case UnaryOpcode.BOOLEAN_NOT, UnaryOp(opcode=UnaryOpcode.BOOLEAN_NOT):
            return inner.operand
        case (
            UnaryOpcode.TRUNCATE,
            UnaryOp(
                opcode=UnaryOpcode.ZERO_EXTEND | UnaryOpcode.SIGN_EXTEND | UnaryOpcode.TRUNCATE
            ),
        ):
            source = inner.operand
            if source.width == op.output.width:
                return source
            if source.width > op.output.width:
                return replace(op, operand=source)
            return replace(op, opcode=inner.opcode, operand=source)
        case UnaryOpcode.ZERO_EXTEND, UnaryOp(opcode=UnaryOpcode.ZERO_EXTEND):
            return replace(op, operand=inner.operand)
        case UnaryOpcode.SIGN_EXTEND, UnaryOp(opcode=UnaryOpcode.SIGN_EXTEND):
            return replace(op, operand=inner.operand)
        case UnaryOpcode.TRUNCATE, BinaryOp(opcode=opcode) if opcode in _LOW_BITS_OPCODES:
            # The low n bits of these results depend only on the low n bits of the operands.
            left = _low_part(inner.left, op.output.width, definitions)
            right = _low_part(inner.right, op.output.width, definitions)
            if left is None or right is None:
                return op
            return BinaryOp(opcode, op.output, left, right, op.origin)
        case UnaryOpcode.TRUNCATE, Piece():
            if op.output.width == inner.low.width:
                return inner.low
            if op.output.width < inner.low.width:
                return replace(op, operand=inner.low)
            return op
        case _:
            return op


_LOW_BITS_OPCODES = frozenset(
    {
        BinaryOpcode.ADD,
        BinaryOpcode.SUB,
        BinaryOpcode.MUL,
        BinaryOpcode.AND,
        BinaryOpcode.OR,
        BinaryOpcode.XOR,
    }
)


def _low_part(operand: Operand, width: int, definitions: Definitions) -> Operand | None:
    """The low `width` bits of `operand`, if available without a new operation."""
    if isinstance(operand, Const):
        return _const(operand.value, width)
    inner = definitions.get(operand.id)
    if (
        isinstance(inner, UnaryOp)
        and inner.opcode in (UnaryOpcode.ZERO_EXTEND, UnaryOpcode.SIGN_EXTEND)
        and inner.operand.width == width
    ):
        return inner.operand
    return None


def _subpiece(op: Subpiece, definitions: Definitions) -> Operation | Operand:
    operand, low_bit, width = op.operand, op.low_bit, op.output.width
    if isinstance(operand, Const):
        return _const(semantics.subpiece(operand.value, low_bit, width), width)
    if low_bit == 0:
        if width == operand.width:
            return operand
        if width < operand.width:
            return UnaryOp(UnaryOpcode.TRUNCATE, op.output, operand, op.origin)
    if low_bit >= operand.width:
        return _const(0, width)
    inner = definitions.get(operand.id)
    if isinstance(inner, Piece):
        low_width = inner.low.width
        if low_bit >= low_width:
            return _narrow(op, inner.high, low_bit - low_width)
        if low_bit + width <= low_width:
            return _narrow(op, inner.low, low_bit)
    if isinstance(inner, UnaryOp) and inner.opcode is UnaryOpcode.ZERO_EXTEND:
        source = inner.operand
        if low_bit >= source.width:
            return _const(0, width)
        if low_bit + width <= source.width:
            return _narrow(op, source, low_bit)
    if isinstance(inner, Subpiece) and low_bit + width <= inner.output.width:
        # Only when the outer range lies within the inner one: past it, the inner
        # subpiece supplies zero bits, not the source's.
        return replace(op, operand=inner.operand, low_bit=inner.low_bit + low_bit)
    return op


def _narrow(op: Subpiece, source: Operand, low_bit: int) -> Operation | Operand:
    """`width` bits of `source` starting at `low_bit`, as simply as possible."""
    width = op.output.width
    if low_bit == 0 and width == source.width:
        return source
    if low_bit + width > source.width:
        return op
    if low_bit == 0:
        return UnaryOp(UnaryOpcode.TRUNCATE, op.output, source, op.origin)
    return replace(op, operand=source, low_bit=low_bit)


def _piece(op: Piece, definitions: Definitions) -> Operation | Operand:
    high, low = op.high, op.low
    if isinstance(high, Const) and isinstance(low, Const):
        return _const(semantics.piece(high.value, low.value, low.width), op.output.width)
    if isinstance(high, Const) and high.value == 0:
        return UnaryOp(UnaryOpcode.ZERO_EXTEND, op.output, low, op.origin)
    if isinstance(high, Var) and isinstance(low, Var):
        upper = definitions.get(high.id)
        lower = definitions.get(low.id)
        if (
            isinstance(upper, Subpiece)
            and upper.low_bit == low.width
            and upper.operand.width == op.output.width
            and _low_bits_of(lower, upper.operand, low.width)
        ):
            return upper.operand
    return op


def _low_bits_of(operation: Operation | None, source: Operand, width: int) -> bool:
    if isinstance(operation, UnaryOp) and operation.opcode is UnaryOpcode.TRUNCATE:
        return operation.operand == source and operation.output.width == width
    if isinstance(operation, Subpiece):
        return (
            operation.operand == source
            and operation.low_bit == 0
            and operation.output.width == width
        )
    return False

"""Common subexpression elimination over the dominator tree.

A side-effect-free operation that repeats an operation dominating it, with the same
opcode, operands, and widths, is replaced by the earlier result.
"""

from __future__ import annotations

from ppy_rev.ir.cfg import control_flow
from ppy_rev.ir.model import (
    BinaryOp,
    Function,
    Operand,
    Operation,
    Piece,
    Subpiece,
    UnaryOp,
    Var,
)
from ppy_rev.ir.transform import map_operation, resolver, substitute
from ppy_rev.simplify.dce import is_removable

type _Key = tuple[object, ...]


def eliminate_common_subexpressions(function: Function) -> Function:
    flow = control_flow(function)
    children: list[list[int]] = [[] for _ in function.blocks]
    for block_id, dominator in enumerate(flow.immediate_dominators):
        if dominator is not None:
            children[dominator].append(block_id)
    replacements: dict[int, Operand] = {}
    use = resolver(replacements)
    stack: list[tuple[int, dict[_Key, Operand]]] = [(0, {})]
    while stack:
        block_id, inherited = stack.pop()
        available = dict(inherited)
        for operation in function.blocks[block_id].operations:
            current = map_operation(operation, use)
            key = _key(current)
            if key is None:
                continue
            output = _output(current)
            if key in available:
                replacements[output.id] = available[key]
            else:
                available[key] = output
        stack.extend((child, available) for child in reversed(children[block_id]))
    return substitute(function, replacements)


def _key(operation: Operation) -> _Key | None:
    if not is_removable(operation):
        return None
    match operation:
        case BinaryOp():
            return ("binary", operation.opcode, operation.left, operation.right)
        case UnaryOp():
            return ("unary", operation.opcode, operation.operand, operation.output.width)
        case Subpiece():
            return ("subpiece", operation.operand, operation.low_bit, operation.output.width)
        case Piece():
            return ("piece", operation.high, operation.low)
        case _:
            return None


def _output(operation: Operation) -> Var:
    match operation:
        case BinaryOp() | UnaryOp() | Subpiece() | Piece():
            return operation.output
        case _:
            raise TypeError(f"{type(operation).__name__} has no single output")

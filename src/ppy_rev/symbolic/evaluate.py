"""Concrete evaluation of symbolic expressions under an assignment of symbols.

Used to check solver models against ppy-rev's own semantics rather than trusting the
solver's interpretation of the encoding. Booleans evaluate to 0 or 1.
"""

from __future__ import annotations

from collections.abc import Mapping

from ppy_rev.ir import semantics
from ppy_rev.ir.model import BinaryOpcode, mask
from ppy_rev.symbolic.expr import Expr, Op, walk


class UnassignedSymbolError(KeyError):
    pass


def evaluate(root: Expr, assignment: Mapping[str, int]) -> int:
    values: dict[int, int] = {}
    for node in walk(root):
        values[id(node)] = _evaluate_node(
            node, [values[id(child)] for child in node.args], assignment
        )
    return values[id(root)]


def _evaluate_node(node: Expr, args: list[int], assignment: Mapping[str, int]) -> int:
    width = node.width
    match node.op:
        case Op.CONST:
            return node.value
        case Op.SYMBOL:
            if node.name not in assignment:
                raise UnassignedSymbolError(node.name)
            return assignment[node.name] & mask(width)
        case Op.ADD:
            return (args[0] + args[1]) & mask(width)
        case Op.SUB:
            return (args[0] - args[1]) & mask(width)
        case Op.MUL:
            return (args[0] * args[1]) & mask(width)
        case Op.UDIV:
            return args[0] // args[1] if args[1] else mask(width)
        case Op.UREM:
            return args[0] % args[1] if args[1] else args[0]
        case Op.SDIV:
            if args[1] == 0:
                return 1 if semantics.to_signed(args[0], width) < 0 else mask(width)
            return semantics.binary(BinaryOpcode.SIGNED_DIV, args[0], args[1], width)
        case Op.SREM:
            if args[1] == 0:
                return args[0]
            return semantics.binary(BinaryOpcode.SIGNED_REM, args[0], args[1], width)
        case Op.AND:
            return args[0] & args[1]
        case Op.OR:
            return args[0] | args[1]
        case Op.XOR:
            return args[0] ^ args[1]
        case Op.NOT:
            return args[0] ^ mask(width)
        case Op.NEG:
            return -args[0] & mask(width)
        case Op.SHL:
            return semantics.binary(BinaryOpcode.SHIFT_LEFT, args[0], args[1], width)
        case Op.LSHR:
            return args[0] >> args[1]
        case Op.ASHR:
            return semantics.binary(BinaryOpcode.ARITHMETIC_SHIFT_RIGHT, args[0], args[1], width)
        case Op.CONCAT:
            return (args[0] << node.args[1].width) | args[1]
        case Op.EXTRACT:
            return (args[0] >> node.value) & mask(width)
        case Op.ZERO_EXTEND:
            return args[0]
        case Op.SIGN_EXTEND:
            return semantics.to_signed(args[0], node.args[0].width) & mask(width)
        case Op.ITE:
            return args[1] if args[0] else args[2]
        case Op.EQ:
            return int(args[0] == args[1])
        case Op.ULT:
            return int(args[0] < args[1])
        case Op.ULE:
            return int(args[0] <= args[1])
        case Op.SLT:
            operand_width = node.args[0].width
            return int(
                semantics.to_signed(args[0], operand_width)
                < semantics.to_signed(args[1], operand_width)
            )
        case Op.SLE:
            operand_width = node.args[0].width
            return int(
                semantics.to_signed(args[0], operand_width)
                <= semantics.to_signed(args[1], operand_width)
            )
        case Op.BOOL_AND:
            return int(all(args))
        case Op.BOOL_OR:
            return int(any(args))
        case Op.BOOL_NOT:
            return 1 - args[0]
        case Op.BOOL_XOR:
            return args[0] ^ args[1]

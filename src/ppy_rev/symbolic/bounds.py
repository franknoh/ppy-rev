"""Sound unsigned interval bounds of bit-vector expressions.

Cheap syntactic over-approximations used to decide whether a symbolic pointer ranges over
few enough addresses to be modeled exactly. Anything not understood is unbounded.
"""

from __future__ import annotations

from ppy_rev.ir.model import mask
from ppy_rev.symbolic.expr import Expr, Op


def unsigned_bounds(expression: Expr) -> tuple[int, int]:
    return _bounds(expression, {})


def _bounds(node: Expr, cache: dict[int, tuple[int, int]]) -> tuple[int, int]:
    known = cache.get(id(node))
    if known is not None:
        return known
    result = _compute(node, cache)
    cache[id(node)] = result
    return result


def _compute(node: Expr, cache: dict[int, tuple[int, int]]) -> tuple[int, int]:
    full = (0, mask(node.width))
    match node.op:
        case Op.CONST:
            return (node.value, node.value)
        case Op.ZERO_EXTEND:
            return _bounds(node.args[0], cache)
        case Op.AND:
            return (0, min(_bounds(argument, cache)[1] for argument in node.args))
        case Op.ADD:
            (low_a, high_a), (low_b, high_b) = (_bounds(argument, cache) for argument in node.args)
            if high_a + high_b <= mask(node.width):
                return (low_a + low_b, high_a + high_b)
            return full
        case Op.MUL:
            (low_a, high_a), (low_b, high_b) = (_bounds(argument, cache) for argument in node.args)
            if high_a * high_b <= mask(node.width):
                return (low_a * low_b, high_a * high_b)
            return full
        case Op.LSHR if node.args[1].is_const:
            low, high = _bounds(node.args[0], cache)
            return (low >> node.args[1].value, high >> node.args[1].value)
        case Op.SHL if node.args[1].is_const:
            low, high = _bounds(node.args[0], cache)
            amount = node.args[1].value
            if (high << amount) <= mask(node.width):
                return (low << amount, high << amount)
            return full
        case Op.UREM if node.args[1].is_const and node.args[1].value > 0:
            return (0, node.args[1].value - 1)
        case Op.EXTRACT if node.value == 0:
            low, high = _bounds(node.args[0], cache)
            if high <= mask(node.width):
                return (low, high)
            return full
        case Op.ITE:
            (low_a, high_a), (low_b, high_b) = (
                _bounds(argument, cache) for argument in node.args[1:]
            )
            return (min(low_a, low_b), max(high_a, high_b))
        case _:
            return full

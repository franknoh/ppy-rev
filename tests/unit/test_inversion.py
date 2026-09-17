"""Equalities over invertible computations are rewritten exactly."""

from __future__ import annotations

from collections.abc import Callable

from hypothesis import given, settings
from hypothesis import strategies as st

from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.evaluate import evaluate
from ppy_rev.symbolic.expr import Expr, Op

X = sx.symbol("x", 16)
Y = sx.symbol("y", 8)

FORMS: dict[str, Callable[[int], Expr]] = {
    "xor": lambda c: sx.bitwise_xor(X, sx.const(c, 16)),
    "add": lambda c: sx.add(X, sx.const(c, 16)),
    "sub": lambda c: sx.sub(X, sx.const(c, 16)),
    "mul": lambda c: sx.mul(X, sx.const(c | 1, 16)),
    "mul even": lambda c: sx.mul(X, sx.const(c & ~1, 16)),
    "not": lambda c: sx.bitwise_not(X),
    "neg": lambda c: sx.negate(X),
    "zext": lambda c: sx.zero_extend(Y, 16),
    "sext": lambda c: sx.sign_extend(Y, 16),
    "concat": lambda c: sx.concat(Y, sx.extract(X, 0, 8)),
}


@settings(max_examples=400, deadline=None)
@given(
    st.sampled_from(sorted(FORMS)),
    st.integers(0, 0xFFFF),
    st.integers(0, 0xFFFF),
    st.integers(0, 0xFFFF),
    st.integers(0, 0xFF),
)
def test_rewritten_equalities_keep_their_meaning(
    form: str, constant: int, target: int, x: int, y: int
) -> None:
    computed = FORMS[form](constant)
    condition = sx.equal(computed, sx.const(target, 16))
    assignment = {"x": x, "y": y}
    assert evaluate(condition, assignment) == int(evaluate(computed, assignment) == target)


def test_invertible_forms_reduce_to_the_input() -> None:
    assert sx.equal(sx.mul(X, sx.const(3, 16)), sx.const(0x0009, 16)) is sx.equal(
        X, sx.const(3, 16)
    )
    assert sx.equal(sx.bitwise_not(X), sx.const(0xFFFE, 16)) is sx.equal(X, sx.const(1, 16))
    assert sx.equal(sx.zero_extend(Y, 16), sx.const(0x100, 16)) is sx.FALSE
    words = sx.equal(sx.concat(Y, sx.extract(X, 0, 8)), sx.const(0x4142, 16))
    assert words.op is Op.BOOL_AND

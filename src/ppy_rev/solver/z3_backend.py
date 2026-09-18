"""Z3 implementation of the solver backend."""

from __future__ import annotations

from collections.abc import Sequence

import z3

from ppy_rev.ir.model import FLOAT_WIDTHS
from ppy_rev.solver.backend import CheckResult, Status
from ppy_rev.symbolic.expr import BOOL, Expr, Op, Rounding, walk

_INTEGRAL_ROUNDING = {
    Rounding.CEILING: z3.RTP,
    Rounding.FLOOR: z3.RTN,
    Rounding.NEAREST: z3.RNA,
}
"""How `fp.roundToIntegral` rounds: toward +inf, toward -inf, or to nearest, ties away."""


class Z3Backend:
    name = "z3"

    def session(self) -> Z3Session:
        return Z3Session()


class Z3Session:
    def __init__(self) -> None:
        self._context = z3.Context()
        self._solver = z3.Solver(ctx=self._context)
        self._bits: dict[Expr, z3.BitVecRef] = {}
        self._bools: dict[Expr, z3.BoolRef] = {}
        self._symbols: dict[str, int] = {}

    def add(self, constraint: Expr) -> None:
        self._solver.add(self.boolean(constraint))

    def push(self) -> None:
        self._solver.push()

    def pop(self) -> None:
        self._solver.pop()

    def check(
        self,
        assumptions: Sequence[Expr] = (),
        symbols: Sequence[Expr] = (),
        timeout_ms: int | None = None,
    ) -> CheckResult:
        self._solver.set("timeout", 0 if timeout_ms is None else max(1, timeout_ms))
        booleans = [self.boolean(assumption).as_ast() for assumption in assumptions]
        # `Solver.check` would cast and sort-check every assumption again in Python, which
        # costs more than solving on long paths; these are translated booleans already.
        outcome = z3.CheckSatResult(
            z3.Z3_solver_check_assumptions(
                self._context.ref(),
                self._solver.solver,
                len(booleans),
                (z3.Ast * len(booleans))(*booleans),
            )
        )
        if outcome == z3.sat:
            model = self._solver.model()
            return CheckResult(
                Status.SAT,
                {
                    item.name: model.eval(self.bits(item), model_completion=True).as_long()
                    for item in symbols
                },
            )
        if outcome == z3.unsat:
            return CheckResult(Status.UNSAT, {})
        reason = self._solver.reason_unknown()
        status = Status.TIMEOUT if reason in ("timeout", "canceled") else Status.UNKNOWN
        return CheckResult(status, {}, reason)

    def smt2(self, assumptions: Sequence[Expr] = ()) -> str:
        self.push()
        try:
            for assumption in assumptions:
                self.add(assumption)
            return self._solver.to_smt2()
        finally:
            self.pop()

    # -- translation ---------------------------------------------------------------------

    def boolean(self, expr: Expr) -> z3.BoolRef:
        if not expr.is_bool:
            raise ValueError("expected a boolean expression")
        self._translate(expr)
        return self._bools[expr]

    def bits(self, expr: Expr) -> z3.BitVecRef:
        if expr.is_bool:
            raise ValueError("expected a bit-vector expression")
        self._translate(expr)
        return self._bits[expr]

    def _translate(self, root: Expr) -> None:
        if root in self._bits or root in self._bools:
            return
        for node in walk(root):
            if node in self._bits or node in self._bools:
                continue
            if node.width == BOOL:
                self._bools[node] = self._boolean_node(node)
            else:
                self._bits[node] = self._bits_node(node)

    def _float_sort(self, width: int) -> z3.FPSortRef:
        if width not in FLOAT_WIDTHS:
            raise ValueError(f"{width}-bit floating point is not modeled")
        return z3.Float32(self._context) if width == 32 else z3.Float64(self._context)

    def _as_float(self, bits: z3.BitVecRef) -> z3.FPRef:
        """Read a bit vector as the IEEE-754 number it encodes, without changing any bit."""
        return z3.fpBVToFP(bits, self._float_sort(bits.size()), self._context)

    def _as_bits(self, number: z3.FPRef) -> z3.BitVecRef:
        return z3.fpToIEEEBV(number, self._context)

    @property
    def _rounding(self) -> z3.FPRMRef:
        """Round to nearest, ties to even: what a compiler emits unless it says otherwise."""
        return z3.RNE(self._context)

    def _boolean_node(self, node: Expr) -> z3.BoolRef:
        bits = [self._bits[child] for child in node.args if not child.is_bool]
        flags = [self._bools[child] for child in node.args if child.is_bool]
        match node.op:
            case Op.CONST:
                return z3.BoolVal(bool(node.value), self._context)
            case Op.EQ:
                return bits[0] == bits[1]
            case Op.ULT:
                return z3.ULT(bits[0], bits[1])
            case Op.ULE:
                return z3.ULE(bits[0], bits[1])
            case Op.SLT:
                return bits[0] < bits[1]
            case Op.SLE:
                return bits[0] <= bits[1]
            case Op.BOOL_AND:
                return z3.And(*flags)
            case Op.BOOL_OR:
                return z3.Or(*flags)
            case Op.BOOL_NOT:
                return z3.Not(flags[0])
            case Op.BOOL_XOR:
                return z3.Xor(flags[0], flags[1])
            case Op.FLOAT_EQ:
                return z3.fpEQ(self._as_float(bits[0]), self._as_float(bits[1]), self._context)
            case Op.FLOAT_LT:
                return z3.fpLT(self._as_float(bits[0]), self._as_float(bits[1]), self._context)
            case Op.FLOAT_LE:
                return z3.fpLEQ(self._as_float(bits[0]), self._as_float(bits[1]), self._context)
            case Op.FLOAT_IS_NAN:
                return z3.fpIsNaN(self._as_float(bits[0]), self._context)
            case _:
                raise ValueError(f"{node.op} does not produce a boolean")

    def _bits_node(self, node: Expr) -> z3.BitVecRef:
        width = node.width
        args = [self._bits[child] for child in node.args if not child.is_bool]
        match node.op:
            case Op.CONST:
                return z3.BitVecVal(node.value, width, self._context)
            case Op.SYMBOL:
                known = self._symbols.setdefault(node.name, width)
                if known != width:
                    raise ValueError(f"symbol {node.name} used with widths {known} and {width}")
                return z3.BitVec(node.name, width, self._context)
            case Op.ADD:
                return args[0] + args[1]
            case Op.SUB:
                return args[0] - args[1]
            case Op.MUL:
                return args[0] * args[1]
            case Op.UDIV:
                return z3.UDiv(args[0], args[1])
            case Op.SDIV:
                return args[0] / args[1]
            case Op.UREM:
                return z3.URem(args[0], args[1])
            case Op.SREM:
                return z3.SRem(args[0], args[1])
            case Op.AND:
                return args[0] & args[1]
            case Op.OR:
                return args[0] | args[1]
            case Op.XOR:
                return args[0] ^ args[1]
            case Op.NOT:
                return ~args[0]
            case Op.NEG:
                return -args[0]
            case Op.SHL:
                return args[0] << args[1]
            case Op.LSHR:
                return z3.LShR(args[0], args[1])
            case Op.ASHR:
                return args[0] >> args[1]
            case Op.CONCAT:
                return z3.Concat(args[0], args[1])
            case Op.EXTRACT:
                return z3.Extract(node.value + width - 1, node.value, args[0])
            case Op.ZERO_EXTEND:
                return z3.ZeroExt(node.value, args[0])
            case Op.SIGN_EXTEND:
                return z3.SignExt(node.value, args[0])
            case Op.ITE:
                return z3.If(self._bools[node.args[0]], args[0], args[1])
            case Op.FLOAT_ADD:
                return self._as_bits(
                    z3.fpAdd(
                        self._rounding,
                        self._as_float(args[0]),
                        self._as_float(args[1]),
                        self._context,
                    )
                )
            case Op.FLOAT_SUB:
                return self._as_bits(
                    z3.fpSub(
                        self._rounding,
                        self._as_float(args[0]),
                        self._as_float(args[1]),
                        self._context,
                    )
                )
            case Op.FLOAT_MUL:
                return self._as_bits(
                    z3.fpMul(
                        self._rounding,
                        self._as_float(args[0]),
                        self._as_float(args[1]),
                        self._context,
                    )
                )
            case Op.FLOAT_DIV:
                return self._as_bits(
                    z3.fpDiv(
                        self._rounding,
                        self._as_float(args[0]),
                        self._as_float(args[1]),
                        self._context,
                    )
                )
            case Op.FLOAT_NEG:
                return self._as_bits(z3.fpNeg(self._as_float(args[0]), self._context))
            case Op.FLOAT_ABS:
                return self._as_bits(z3.fpAbs(self._as_float(args[0]), self._context))
            case Op.FLOAT_SQRT:
                return self._as_bits(
                    z3.fpSqrt(self._rounding, self._as_float(args[0]), self._context)
                )
            case Op.FLOAT_INTEGRAL:
                mode = _INTEGRAL_ROUNDING[Rounding(node.value)](self._context)
                return self._as_bits(
                    z3.fpRoundToIntegral(mode, self._as_float(args[0]), self._context)
                )
            case Op.FLOAT_FROM_SIGNED:
                return self._as_bits(
                    z3.fpSignedToFP(self._rounding, args[0], self._float_sort(width), self._context)
                )
            case Op.FLOAT_TO_FLOAT:
                return self._as_bits(
                    z3.fpFPToFP(
                        self._rounding,
                        self._as_float(args[0]),
                        self._float_sort(width),
                        self._context,
                    )
                )
            case Op.FLOAT_TO_SIGNED:
                # RevIR defines the cases IEEE leaves open: a NaN or an infinity gives zero.
                number = self._as_float(args[0])
                defined = z3.Or(
                    z3.fpIsNaN(number, self._context), z3.fpIsInf(number, self._context)
                )
                zero = z3.BitVecVal(0, width, self._context)
                return z3.If(
                    defined,
                    zero,
                    z3.fpToSBV(
                        z3.RTZ(self._context),
                        number,
                        z3.BitVecSort(width, self._context),
                        self._context,
                    ),
                )
            case _:
                raise ValueError(f"{node.op} does not produce a bit vector")

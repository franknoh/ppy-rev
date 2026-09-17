"""Function-level symbolic solving on compiled checks, verified by native execution."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from conftest import FixtureCompiler
from ppy_rev import Analyzer
from ppy_rev.lift.lifter import lift_export
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.executor import Goal
from ppy_rev.symbolic.harness import solve_function

pytestmark = [pytest.mark.ghidra, pytest.mark.native]

SOURCE = Path(__file__).parents[1] / "fixtures" / "src" / "solve_functions.c"
CHECKS = re.findall(r"^CHECK uint64_t (\w+)\(", SOURCE.read_text(), flags=re.MULTILINE)
VARIANTS = [(compiler, level) for compiler in ("gcc", "clang") for level in ("O0", "O2")]


def _returns_one(outputs: dict[str, sx.Expr]) -> sx.Expr:
    rax = outputs["RAX"]
    return sx.equal(sx.extract(rax, 0, 8), sx.const(1, 8))


@pytest.mark.parametrize(("compiler", "optimization"), VARIANTS)
def test_symbolic_solutions_satisfy_native_checks(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    compiler: str,
    optimization: str,
) -> None:
    binary = compile_fixture.build("solve_functions", compiler, optimization)
    module = simplify_module(lift_export(analyzer.export(binary)).module)
    solutions: dict[str, tuple[int, int]] = {}
    for name in CHECKS:
        function = module.function_named(name)
        assert function is not None, name
        x, y = sx.symbol("x", 64), sx.symbol("y", 64)
        result = solve_function(
            module,
            function,
            {"RDI": x, "RSI": y},
            Goal(on_return=_returns_one),
            Z3Backend(),
        )
        assert result.exploration.incomplete == [], (name, result.exploration.incomplete)
        assert result.model is not None, name
        solutions[name] = (result.model.get("x", 0), result.model.get("y", 0))
    stdin = "".join(f"{name} {x} {y}\n" for name, (x, y) in solutions.items())
    completed = subprocess.run(
        [str(binary)], input=stdin, capture_output=True, text=True, check=True, timeout=60
    )
    assert dict(zip(solutions, completed.stdout.split(), strict=True)) == dict.fromkeys(
        solutions, "1"
    )

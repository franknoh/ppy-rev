"""RevIR interpreter versus native execution of the same compiled probes.

Each probe in tests/fixtures/src/arith_ops.c is run natively (batched through stdin) and
through Ghidra → RevIR → interpreter on identical inputs; results must agree exactly.
"""

from __future__ import annotations

import random
import re
import subprocess
from pathlib import Path

import pytest

from conftest import FixtureCompiler
from ppy_rev import Analyzer
from ppy_rev.execution.interpreter import Interpreter
from ppy_rev.execution.process import enter_call, standard_memory
from ppy_rev.ir.model import Module
from ppy_rev.ir.validate import validate_module
from ppy_rev.lift.lifter import lift_export

pytestmark = [pytest.mark.ghidra, pytest.mark.native]

SOURCE = Path(__file__).parents[1] / "fixtures" / "src" / "arith_ops.c"
PROBES = re.findall(r"^PROBE uint64_t (\w+)\(", SOURCE.read_text(), flags=re.MULTILINE)
EDGES = [
    0,
    1,
    2,
    3,
    7,
    8,
    31,
    32,
    63,
    64,
    0x7F,
    0x80,
    0xFF,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x7FFFFFFF,
    0x80000000,
    0xFFFFFFFF,
    0x1_0000_0000,
    0x7FFFFFFFFFFFFFFF,
    0x8000000000000000,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
]
RANDOM_CASES = 24
VARIANTS = [
    (compiler, level) for compiler in ("gcc", "clang") for level in ("O0", "O1", "O2", "O3")
]


def _inputs(name: str) -> list[tuple[int, int]]:
    generator = random.Random(f"arith_ops:{name}")
    pairs = [(a, b) for a in EDGES[::3] for b in EDGES[1::3]]
    pairs += [(generator.getrandbits(64), generator.getrandbits(64)) for _ in range(RANDOM_CASES)]
    pairs += [(generator.getrandbits(8), generator.getrandbits(6)) for _ in range(RANDOM_CASES)]
    return pairs


def _native(binary: Path, cases: list[tuple[str, int, int]]) -> list[int]:
    stdin = "".join(f"{name} {a} {b}\n" for name, a, b in cases)
    completed = subprocess.run(
        [str(binary)], input=stdin, capture_output=True, text=True, check=True, timeout=60
    )
    return [int(line) for line in completed.stdout.split()]


def _interpret(module: Module, name: str, a: int, b: int) -> int:
    function = module.function_named(name)
    assert function is not None, name
    memory = standard_memory(module)
    frame = enter_call(module, memory, {"RDI": a, "RSI": b})
    outputs = Interpreter(module, memory).call(function, frame.registers, frame.return_address)
    stack_pointer = module.target.stack_pointer
    assert outputs[stack_pointer] == frame.registers[stack_pointer] + 8, f"{name} unbalanced stack"
    return outputs["RAX"]


@pytest.mark.parametrize(("compiler", "optimization"), VARIANTS)
def test_interpreter_matches_native_execution(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    compiler: str,
    optimization: str,
) -> None:
    binary = compile_fixture.build("arith_ops", compiler, optimization)
    module = lift_export(analyzer.export(binary)).module
    assert validate_module(module) == []
    cases = [(name, a, b) for name in PROBES for a, b in _inputs(name)]
    expected = _native(binary, cases)
    assert len(expected) == len(cases)
    mismatches = [
        f"{name}({a:#x}, {b:#x}): native {want:#x}, interpreter {got:#x}"
        for (name, a, b), want in zip(cases, expected, strict=True)
        if (got := _interpret(module, name, a, b)) != want
    ]
    assert mismatches == []

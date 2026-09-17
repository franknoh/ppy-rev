"""Lifting bytecode out of compiled interpreters, checked against the interpreters themselves.

For each fixture and compiler variant the interpreter is specialized to its bytecode, and
then concrete RevIR execution of the program with the lifted bytecode must agree exactly
with execution of the program as lifted from the binary, on the right input and on many
wrong ones.
"""

from __future__ import annotations

import random

import pytest

from conftest import FixtureCompiler
from ppy_rev import Analyzer
from ppy_rev.analysis.program import find_main
from ppy_rev.execution.run import run_program
from ppy_rev.ir.validate import validate_module
from ppy_rev.solve import SolveRequest
from ppy_rev.vm.lift import lift_vm, patch_interpreter

pytestmark = [pytest.mark.ghidra, pytest.mark.native]

FIXTURES = {
    # name: (answer, instructions in the bytecode, opcodes it uses, halting opcodes)
    "simple_vm": (
        b"vM_l1ft!",
        18,
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B},
        {0xF0, 0xFF},
    ),
    "vm_check": (b"Vm_0k!", 32, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x88}, {0x00, 0x77}),
}
VARIANTS = [(compiler, level) for compiler in ("gcc", "clang") for level in ("O0", "O2")]


@pytest.mark.parametrize("name", sorted(FIXTURES))
@pytest.mark.parametrize(("compiler", "level"), VARIANTS)
def test_lifted_bytecode_behaves_like_the_interpreter(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    name: str,
    compiler: str,
    level: str,
) -> None:
    answer, instructions, opcodes, halting = FIXTURES[name]
    binary = compile_fixture.build(name, compiler, level)
    module = analyzer.simplified(binary)
    request = SolveRequest(binary=binary)
    lifted = lift_vm(module, request)
    seen = {item.opcode for item in lifted.instructions}
    assert seen <= opcodes | halting
    # An optimizer may run a handler without going back around the dispatch loop (gcc
    # decodes ADD right after a push), so that instruction is lifted with its predecessor.
    assert len(seen & opcodes) >= len(opcodes) - 1
    counters = {item.counter for item in lifted.instructions}
    assert len(counters) <= instructions
    assert all(item.bytes and item.bytes[0] == item.opcode for item in lifted.instructions)
    patched = patch_interpreter(module, lifted)
    assert validate_module(patched) == []
    generator = random.Random(f"{name}:{compiler}:{level}")
    inputs = [answer, answer[:-1] + b"?", b"", answer + b"x"]
    inputs += [
        bytes(generator.randrange(0x20, 0x7F) for _ in range(len(answer))) for _ in range(12)
    ]
    reserve = {1: request.max_length + 1}  # argv laid out as the lifting exploration saw it
    for data in inputs:
        arguments = [f"./{module.name}".encode(), data]
        original = run_program(module, find_main(module), arguments, reserve=reserve)
        lifted_run = run_program(patched, find_main(patched), arguments, reserve=reserve)
        assert (lifted_run.outcome, lifted_run.stdout) == (original.outcome, original.stdout), data


def test_lifted_bytecode_refuses_other_interpreter_states(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler]
) -> None:
    binary = compile_fixture.build("simple_vm", "gcc", "O2")
    module = analyzer.simplified(binary)
    patched = patch_interpreter(module, lift_vm(module, SolveRequest(binary=binary)))
    # Without the reserved argv space the input string lands elsewhere: a guard stops.
    run = run_program(patched, find_main(patched), [b"./simple_vm", b"vM_l1ft!"])
    assert "not specialized for" in run.outcome

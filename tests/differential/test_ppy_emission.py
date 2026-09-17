"""Emitted PPy versus the RevIR interpreter on the arithmetic probes.

The emitted directory must pass `ppy check` with no errors and no inserted runtime
checks, and running it under CPython must agree with the interpreter on every input.
"""

from __future__ import annotations

import importlib
import random
import re
import subprocess
import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

import pytest

from conftest import FixtureCompiler
from ppy_rev import Analyzer
from ppy_rev.analysis.program import find_main
from ppy_rev.execution.interpreter import Interpreter
from ppy_rev.execution.process import (
    INITIAL_STACK_POINTER,
    RETURN_SENTINEL,
    STACK_CANARY,
    STACK_SIZE,
    STACK_START,
    THREAD_BLOCK,
    THREAD_BLOCK_SIZE,
    enter_call,
    standard_memory,
)
from ppy_rev.execution.run import run_program
from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.ppy.check import check_ppy
from ppy_rev.ppy.emit import EmittedFunction, emit_module
from ppy_rev.simplify.pipeline import simplify_module

pytestmark = [pytest.mark.ghidra, pytest.mark.native]

SOURCE = Path(__file__).parents[1] / "fixtures" / "src" / "arith_ops.c"
PROBES = re.findall(r"^PROBE uint64_t (\w+)\(", SOURCE.read_text(), flags=re.MULTILINE)
VARIANTS = [(compiler, level) for compiler in ("gcc", "clang") for level in ("O0", "O2")]
CASES = 12


@contextmanager
def _emitted(directory: Path) -> Generator[ModuleType]:
    importlib.import_module("ppy")  # installs the .ppy import hook
    for name in ("module", "runtime"):
        sys.modules.pop(name, None)
    sys.path.insert(0, str(directory))
    try:
        yield importlib.import_module("module")
    finally:
        sys.path.remove(str(directory))
        for name in ("module", "runtime"):
            sys.modules.pop(name, None)


def _interpret(module: Module, name: str, a: int, b: int) -> int:
    function = module.function_named(name)
    assert function is not None
    memory = standard_memory(module)
    frame = enter_call(module, memory, {"RDI": a, "RSI": b})
    return Interpreter(module, memory).call(function, frame.registers, frame.return_address)["RAX"]


def _run_emitted(emitted: ModuleType, function: EmittedFunction, a: int, b: int) -> int:
    runtime = sys.modules["runtime"]
    machine = emitted.new_machine()
    machine.memory.map(runtime.Region("[stack]", STACK_START, STACK_SIZE, True, b""))
    machine.memory.map(runtime.Region("[tls]", THREAD_BLOCK, THREAD_BLOCK_SIZE, True, b""))
    machine.memory.store(THREAD_BLOCK + 0x28, 8, STACK_CANARY)
    stack_pointer = INITIAL_STACK_POINTER - 8
    machine.memory.store(stack_pointer, 8, RETURN_SENTINEL)
    registers = {"RDI": a, "RSI": b, "RSP": stack_pointer, "FS_OFFSET": THREAD_BLOCK}
    run: Callable[..., tuple[int, ...]] = getattr(emitted, function.python_name)
    outputs = run(machine, *(registers.get(register, 0) for register, _ in function.parameters))
    return outputs[function.outputs.index("RAX")]


@pytest.mark.parametrize(("compiler", "optimization"), VARIANTS)
def test_emitted_ppy_checks_and_matches_interpreter(
    analyzer: Analyzer,
    compile_fixture: type[FixtureCompiler],
    tmp_path: Path,
    compiler: str,
    optimization: str,
) -> None:
    binary = compile_fixture.build("arith_ops", compiler, optimization)
    module = simplify_module(lift_export(analyzer.export(binary)).module)
    emitted = emit_module(module)
    emitted.write(tmp_path)
    result = check_ppy(tmp_path)
    assert result.errors == ()
    assert result.checked_conversions == ()
    functions = {function.name: function for function in emitted.functions}
    generator = random.Random(f"ppy:{compiler}:{optimization}")
    with _emitted(tmp_path) as loaded:
        for name in PROBES:
            for _ in range(CASES):
                a, b = generator.getrandbits(64), generator.getrandbits(generator.choice((6, 64)))
                expected = _interpret(module, name, a, b)
                assert _run_emitted(loaded, functions[name], a, b) == expected, (name, a, b)


PROGRAMS = {
    "xor_check": ([b"./xor_check", b"rev_is_easy"], b"", b"Correct!\n"),
    "strcmp_argv": ([b"./strcmp_argv", b"nope"], b"", b"Wrong!\n"),
    "fgets_check": ([b"./fgets_check"], b"gg/dq2_o2sr\n", b"Password:\nAccess granted\n"),
    "scanf_check": ([b"./scanf_check"], b"nope\n", b"Key: Wrong\n"),
}


@pytest.mark.parametrize("name", sorted(PROGRAMS))
def test_emitted_program_runs_like_the_interpreter(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler], tmp_path: Path, name: str
) -> None:
    """The emitted PPy is a working program: the same output as the RevIR interpreter."""
    arguments, stdin, expected = PROGRAMS[name]
    module = analyzer.simplified(compile_fixture.build(name, "gcc", "O2"))
    emit_module(module).write(tmp_path)
    interpreted = run_program(module, find_main(module), arguments, stdin)
    assert interpreted.stdout == expected, interpreted
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "ppy_compiler",
            "--color",
            "never",
            str(tmp_path / "program.ppy"),
            "--",
            *(item.decode() for item in arguments[1:]),
        ],
        input=stdin,
        capture_output=True,
        cwd=tmp_path,
        timeout=600,
    )
    assert completed.stderr == b"", completed.stderr.decode()
    assert completed.stdout == expected
    assert f"main returned {completed.returncode}" == interpreted.outcome

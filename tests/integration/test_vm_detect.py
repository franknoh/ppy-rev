"""VM dispatcher detection on compiled bytecode interpreters and on ordinary programs."""

from __future__ import annotations

import pytest

from conftest import FixtureCompiler
from ppy_rev import Analyzer
from ppy_rev.vm.detect import LIKELY_DISPATCHER, Dispatcher, detect_dispatchers

pytestmark = [pytest.mark.ghidra, pytest.mark.native]

VARIANTS = [(compiler, level) for compiler in ("gcc", "clang") for level in ("O0", "O2")]


def _top(
    analyzer: Analyzer,
    compiler_fixture: type[FixtureCompiler],
    name: str,
    compiler: str,
    level: str,
) -> Dispatcher:
    binary = compiler_fixture.build(name, compiler, level)
    candidates = detect_dispatchers(analyzer.simplified(binary))
    assert candidates, name
    return candidates[0]


def _handlers_by_opcode(dispatcher: Dispatcher) -> dict[int, tuple[int, bool]]:
    return {
        opcode: (handler.address, handler.returns_to_dispatcher)
        for handler in dispatcher.handlers
        for opcode in handler.opcodes
    }


@pytest.mark.parametrize(("compiler", "level"), VARIANTS)
def test_register_vm_dispatcher(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler], compiler: str, level: str
) -> None:
    dispatcher = _top(analyzer, compile_fixture, "simple_vm", compiler, level)
    assert dispatcher.confidence >= 0.8
    assert dispatcher.loop_header is not None
    assert dispatcher.fetch is not None and dispatcher.fetch.width == 8
    assert dispatcher.fetch.program_counter is not None
    by_opcode = _handlers_by_opcode(dispatcher)
    instructions = range(0x01, 0x0C)
    assert all(by_opcode[opcode][1] for opcode in instructions)
    assert len({by_opcode[opcode][0] for opcode in instructions}) == len(instructions)
    assert by_opcode[0xF0][1] is False  # ACCEPT leaves the interpreter loop
    assert any("by different amounts" in item.text for item in dispatcher.evidence)


@pytest.mark.parametrize(("compiler", "level"), VARIANTS)
def test_stack_vm_dispatcher(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler], compiler: str, level: str
) -> None:
    dispatcher = _top(analyzer, compile_fixture, "vm_check", compiler, level)
    assert dispatcher.confidence >= 0.8
    by_opcode = _handlers_by_opcode(dispatcher)
    opcodes = (0x11, 0x22, 0x33, 0x55, 0x66, 0x88)
    assert all(by_opcode[opcode][1] for opcode in opcodes)
    assert len({by_opcode[opcode][0] for opcode in opcodes}) == len(opcodes)
    assert any("by different amounts" in item.text for item in dispatcher.evidence)


@pytest.mark.parametrize("name", ["switch_check", "arith_ops", "strcmp_argv", "class_count"])
def test_ordinary_programs_have_no_likely_dispatcher(
    analyzer: Analyzer, compile_fixture: type[FixtureCompiler], name: str
) -> None:
    for compiler, level in VARIANTS:
        binary = compile_fixture.build(name, compiler, level)
        candidates = detect_dispatchers(analyzer.simplified(binary))
        assert all(candidate.confidence < LIKELY_DISPATCHER for candidate in candidates)

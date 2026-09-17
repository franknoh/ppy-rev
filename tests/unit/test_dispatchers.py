from __future__ import annotations

from ppy_rev.abi import SYSV_X86_64
from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.summaries.libc import modeled_reads
from ppy_rev.vm.detect import LIKELY_DISPATCHER, Dispatcher, detect_dispatchers
from support.exports import ProgramBuilder, const, op, ram, reg, ret, tmp

HEADER = 0x1004
EXIT = 0x1080
LATCH = 0x1070
HANDLERS = (0x1020, 0x1030, 0x1040)


def _loop(steps: tuple[int, int, int] | None, operand: bool = False) -> Module:
    """for (i = 0; data[i]; ) { switch (data[i]) { case 1: ... case 3: ... } i += step }

    With `steps`, each case advances `i` by its own amount and jumps back to the loop
    header; without, every case falls into one shared `i += 1`. With `operand`, the first
    case also reads `data[i + 1]`.
    """
    program = ProgramBuilder()
    program.code(0x1000, [op("COPY", [const(0, 8)], reg("RCX"))])
    program.code(
        HEADER,
        [
            op("INT_ADD", [reg("RDI"), reg("RCX")], tmp(0x100, 8)),
            op("LOAD", [tmp(0x100, 8)], reg("AL")),
        ],
    )
    for index, value in enumerate((0, 1, 2, 3)):
        target = EXIT if value == 0 else HANDLERS[value - 1]
        program.code(
            0x1008 + 4 * index,
            [
                op("INT_EQUAL", [reg("AL"), const(value, 1)], reg("ZF")),
                op("CBRANCH", [ram(target), reg("ZF")]),
            ],
        )
    program.code(0x1018, [op("BRANCH", [ram(LATCH)])])
    for index, handler in enumerate(HANDLERS):
        body = [op("INT_XOR", [reg("RDX"), const(index + 5, 8)], reg("RDX"))]
        if operand and index == 0:
            body = [
                op("INT_ADD", [reg("RDI"), reg("RCX")], tmp(0x200, 8)),
                op("INT_ADD", [tmp(0x200, 8), const(1, 8)], tmp(0x208, 8)),
                op("LOAD", [tmp(0x208, 8)], reg("RDX")),
            ]
        program.code(handler, body)
        if steps is None:
            program.code(handler + 4, [op("BRANCH", [ram(LATCH)])])
        else:
            program.code(
                handler + 4,
                [
                    op("INT_ADD", [reg("RCX"), const(steps[index], 8)], reg("RCX")),
                    op("BRANCH", [ram(HEADER)]),
                ],
            )
    program.code(
        LATCH,
        [
            op("INT_ADD", [reg("RCX"), const(1, 8)], reg("RCX")),
            op("BRANCH", [ram(HEADER)]),
        ],
    )
    program.code(EXIT, [op("COPY", [reg("RDX")], reg("RAX"))])
    program.code(EXIT + 4, ret(), length=1)
    program.function("walk", 0x1000)
    return simplify_module(lift_export(program.build()).module, modeled_reads(SYSV_X86_64))


def _dispatcher(module: Module) -> Dispatcher:
    candidates = detect_dispatchers(module)
    assert len(candidates) == 1
    return candidates[0]


def _evidence(dispatcher: Dispatcher) -> str:
    return "\n".join(item.text for item in dispatcher.evidence)


def test_a_loop_stepping_through_data_is_not_a_likely_vm() -> None:
    dispatcher = _dispatcher(_loop(steps=None))
    assert dispatcher.fetch is not None and dispatcher.fetch.program_counter is not None
    assert dispatcher.confidence < LIKELY_DISPATCHER
    assert "no instruction structure" in _evidence(dispatcher)


def test_instructions_of_different_lengths_make_a_likely_vm() -> None:
    dispatcher = _dispatcher(_loop(steps=(1, 2, 3)))
    assert dispatcher.confidence >= LIKELY_DISPATCHER
    assert "advance the VM program counter by different amounts" in _evidence(dispatcher)


def test_operands_after_the_opcode_make_a_likely_vm() -> None:
    dispatcher = _dispatcher(_loop(steps=None, operand=True))
    assert dispatcher.confidence >= LIKELY_DISPATCHER
    assert "1 handlers read operands from the bytecode" in _evidence(dispatcher)

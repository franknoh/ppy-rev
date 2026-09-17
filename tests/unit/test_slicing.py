from __future__ import annotations

from ppy_rev.abi import SYSV_X86_64
from ppy_rev.analysis.slicing import backward_slice
from ppy_rev.ir.model import Call, Module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.summaries.libc import modeled_reads
from support.exports import ProgramBuilder, call, const, op, ram, reg, ret

PUTS = 0x3000
BANNER = 0x2000
GOAL_CALL = 0x1018


def _module(result_used: bool) -> Module:
    """main: banner(); r = puts(A); if ((result_used ? r : 7) == 7) puts(B); return"""
    program = ProgramBuilder()
    program.import_("puts", PUTS)
    program.code(BANNER, [op("COPY", [const(0x5020, 8)], reg("RDI"))])
    program.code(BANNER + 4, call(PUTS, BANNER + 8))
    program.code(BANNER + 8, ret(), length=1)
    program.function("banner", BANNER)
    program.code(0x1000, call(BANNER, 0x1004))
    program.code(0x1004, [op("COPY", [const(0x5000, 8)], reg("RDI"))])
    program.code(0x1008, call(PUTS, 0x100C))
    checked = reg("RAX") if result_used else reg("RBP")
    program.code(0x100C, [op("INT_EQUAL", [checked, const(7, 8)], reg("ZF"))])
    program.code(
        0x1010,
        [op("BOOL_NEGATE", [reg("ZF")], reg("ZF")), op("CBRANCH", [ram(0x101C), reg("ZF")])],
    )
    program.code(0x1014, [op("COPY", [const(0x5010, 8)], reg("RDI"))])
    program.code(GOAL_CALL, call(PUTS, 0x101C))
    program.code(0x101C, ret(), length=1)
    program.function("main", 0x1000)
    return simplify_module(lift_export(program.build()).module, modeled_reads(SYSV_X86_64))


def _calls(module: Module, name: str) -> dict[int, tuple[int, int, int]]:
    function = module.function_named(name)
    assert function is not None
    return {
        operation.origin.address: (function.entry, block.id, index)
        for block in function.blocks
        for index, operation in enumerate(block.operations)
        if isinstance(operation, Call)
    }


def test_output_that_cannot_matter_is_sliced_away() -> None:
    module = _module(result_used=False)
    program_slice = backward_slice(module, frozenset({GOAL_CALL}), outermost=0x1000)
    main = _calls(module, "main")
    assert program_slice.output_functions == {BANNER}
    assert main[0x1000] in program_slice.skipped  # the helper that only prints
    assert main[0x1008] in program_slice.skipped  # a message nothing depends on
    assert main[GOAL_CALL] not in program_slice.skipped
    assert all(key in program_slice.skipped for key in _calls(module, "banner").values())


def test_calls_whose_results_matter_are_kept() -> None:
    module = _module(result_used=True)
    program_slice = backward_slice(module, frozenset({GOAL_CALL}), outermost=0x1000)
    main = _calls(module, "main")
    assert main[0x1008] not in program_slice.skipped
    assert main[0x1000] in program_slice.skipped


def test_protected_helpers_are_not_output_only() -> None:
    module = _module(result_used=False)
    banner_call = next(iter(_calls(module, "banner")))
    program_slice = backward_slice(module, frozenset({GOAL_CALL, banner_call}), 0x1000)
    assert program_slice.output_functions == frozenset()
    assert _calls(module, "main")[0x1000] not in program_slice.skipped

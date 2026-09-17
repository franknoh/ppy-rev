from __future__ import annotations

from ppy_rev.analysis.program import external_name, find_main
from ppy_rev.ir.model import Call
from ppy_rev.lift.lifter import lift_export
from support.exports import ProgramBuilder, const, op, reg, ret, tmp

START_MAIN = 0x3000
GOT_ENTRY = 0x5000


def test_main_is_found_through_a_got_call() -> None:
    """Stripped PIE `_start`: `lea rdi, main` and `call [rip + __libc_start_main@GOT]`."""
    program = ProgramBuilder()
    program.import_("__libc_start_main", START_MAIN)
    program.data(".got", GOT_ENTRY, START_MAIN.to_bytes(8, "little"))
    program.code(0x1000, [op("COPY", [const(0x1100, 8)], reg("RDI"))])
    program.code(
        0x1004,
        [
            op("LOAD", [const(GOT_ENTRY, 8)], tmp(0x100, 8)),
            op("INT_SUB", [reg("RSP"), const(8, 8)], reg("RSP")),
            op("STORE", [reg("RSP"), const(0x100A, 8)]),
            op("CALLIND", [tmp(0x100, 8)]),
        ],
        length=6,
    )
    program.indirect_flows(0x1004, (START_MAIN,))
    program.code(0x100A, ret(), length=1)
    program.function("entry", 0x1000)
    program.code(0x1100, [op("COPY", [const(0, 8)], reg("RAX"))])
    program.code(0x1104, ret(), length=1)
    program.function("FUN_00001100", 0x1100)
    module = lift_export(program.build()).module
    entry = module.function_named("entry")
    assert entry is not None
    got_call = next(
        operation
        for block in entry.blocks
        for operation in block.operations
        if isinstance(operation, Call)
    )
    assert external_name(module, got_call) == "__libc_start_main"
    assert find_main(module).entry == 0x1100

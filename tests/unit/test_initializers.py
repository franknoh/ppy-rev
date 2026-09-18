from __future__ import annotations

from ppy_rev.analysis.program import initializers
from ppy_rev.lift.lifter import lift_export
from support.exports import ProgramBuilder, call, ret

PTRACE = 0x3000
PUTS = 0x3010
FRAME_DUMMY = 0x1000
CONSTRUCTOR = 0x1100
INIT_ARRAY = 0x4000


def _program() -> ProgramBuilder:
    """A binary whose `.init_array` holds the usual `frame_dummy` and a real constructor."""
    program = ProgramBuilder()
    program.import_("ptrace", PTRACE)
    program.import_("puts", PUTS)
    program.code(FRAME_DUMMY, call(PUTS, FRAME_DUMMY + 4))
    program.code(FRAME_DUMMY + 4, ret(), length=1)
    program.function("frame_dummy", FRAME_DUMMY)
    program.code(CONSTRUCTOR, call(PTRACE, CONSTRUCTOR + 4))
    program.code(CONSTRUCTOR + 4, ret(), length=1)
    program.function("_INIT_1", CONSTRUCTOR)
    return program


def test_a_constructor_that_checks_for_a_debugger_is_reported() -> None:
    program = _program()
    entries = FRAME_DUMMY.to_bytes(8, "little") + CONSTRUCTOR.to_bytes(8, "little")
    program.data(".init_array", INIT_ARRAY, entries)
    module = lift_export(program.build()).module
    assert [(item.name, item.library_calls) for item in initializers(module)] == [
        ("_INIT_1", ("ptrace",))
    ]


def test_ordinary_constructors_are_not_reported() -> None:
    """`frame_dummy` alone is what every compiler emits, and it decides nothing."""
    program = _program()
    program.data(".init_array", INIT_ARRAY, FRAME_DUMMY.to_bytes(8, "little"))
    module = lift_export(program.build()).module
    assert initializers(module) == ()


def test_a_binary_without_init_array_reports_nothing() -> None:
    module = lift_export(_program().build()).module
    assert initializers(module) == ()

from __future__ import annotations

from ppy_rev.analysis.program import deferred_initializers, initializer_functions
from ppy_rev.execution.program import HEAP_START, program_memory
from ppy_rev.execution.startup import run_initializers
from ppy_rev.lift.lifter import lift_export
from support.exports import ProgramBuilder, call, const, op, ret

PTRACE = 0x3000
PUTS = 0x3010
FRAME_DUMMY = 0x1000
CONSTRUCTOR = 0x1100
INIT_ARRAY = 0x4000
TABLE = 0x4100
FILLER = 0x1200
ALLOCATOR = 0x1400
MALLOC = 0x3020


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
    assert [(item.name, item.library_calls) for item in deferred_initializers(module)] == [
        ("_INIT_1", ("ptrace",))
    ]


def test_ordinary_constructors_are_not_reported() -> None:
    """`frame_dummy` alone is what every compiler emits, and it decides nothing."""
    program = _program()
    program.data(".init_array", INIT_ARRAY, FRAME_DUMMY.to_bytes(8, "little"))
    module = lift_export(program.build()).module
    assert deferred_initializers(module) == ()


def test_a_binary_without_init_array_reports_nothing() -> None:
    module = lift_export(_program().build()).module
    assert deferred_initializers(module) == ()
    assert initializer_functions(module) == ()


def test_every_constructor_is_found_in_the_order_the_loader_runs_them() -> None:
    program = _program()
    entries = FRAME_DUMMY.to_bytes(8, "little") + CONSTRUCTOR.to_bytes(8, "little")
    program.data(".init_array", INIT_ARRAY, entries)
    module = lift_export(program.build()).module
    assert [item.name for item in initializer_functions(module)] == ["frame_dummy", "_INIT_1"]


def _filling_program() -> ProgramBuilder:
    """A constructor that writes a table, as a C++ global object's constructor does."""
    program = _program()
    program.code(FILLER, [op("STORE", [const(TABLE, 8), const(0x42, 8)])])
    program.code(FILLER + 4, ret(), length=1)
    program.function("_INIT_2", FILLER)
    program.data(".data", TABLE, bytes(16), writable=True)
    return program


def test_a_constructor_that_fills_memory_runs_before_main() -> None:
    """Main reads what the constructor wrote; starting at main would read zeros instead."""
    program = _filling_program()
    program.data(".init_array", INIT_ARRAY, FILLER.to_bytes(8, "little"))
    module = lift_export(program.build()).module
    memory = program_memory(module)
    assert memory.load(TABLE, 64) == 0
    initialization = run_initializers(module, memory)
    assert initialization.ran == ("_INIT_2",)
    assert initialization.complete
    assert memory.load(TABLE, 64) == 0x42


def test_a_constructor_that_needs_the_input_is_not_run() -> None:
    """One that checks for a debugger cannot be run concretely without deciding for it."""
    program = _filling_program()
    entries = CONSTRUCTOR.to_bytes(8, "little") + FILLER.to_bytes(8, "little")
    program.data(".init_array", INIT_ARRAY, entries)
    module = lift_export(program.build()).module
    memory = program_memory(module)
    initialization = run_initializers(module, memory)
    assert initialization.ran == ("_INIT_2",)  # the rest of them still run
    assert not initialization.complete
    assert initialization.stopped == (("_INIT_1", "it calls ptrace, which needs the input"),)
    assert memory.load(TABLE, 64) == 0x42


def test_two_constructors_do_not_allocate_the_same_memory() -> None:
    """They share the program's heap, so what one keeps the next cannot be handed."""
    program = _program()
    program.import_("malloc", MALLOC)
    for index, entry in enumerate((ALLOCATOR, ALLOCATOR + 0x100)):
        program.code(entry, call(MALLOC, entry + 4))
        program.code(entry + 4, ret(), length=1)
        program.function(f"_INIT_ALLOC_{index}", entry)
    entries = b"".join(address.to_bytes(8, "little") for address in (ALLOCATOR, ALLOCATOR + 0x100))
    program.data(".init_array", INIT_ARRAY, entries)
    module = lift_export(program.build()).module
    memory = program_memory(module)
    initialization = run_initializers(module, memory)
    assert initialization.ran == ("_INIT_ALLOC_0", "_INIT_ALLOC_1")
    # Two allocations happened, so main starts past both of them.
    assert initialization.heap_next > HEAP_START

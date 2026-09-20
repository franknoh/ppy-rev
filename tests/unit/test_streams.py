"""`std::cin` and `std::cout` as objects, which optimized C++ reads without calling."""

from __future__ import annotations

from ppy_rev.execution.program import CXX_CTYPE, CXX_IOS_VTABLE, program_memory
from ppy_rev.lift.lifter import lift_export
from ppy_rev.summaries import cxx
from support.exports import ProgramBuilder, ret

BSS = 0x6000
EXTERNAL = 0x500000


def _program(*, mapped: bool) -> ProgramBuilder:
    """A C++ program whose `std::cin` is either in its own `.bss` or outside the image.

    Both happen: a copy relocation puts the object in the program, and a reference
    through the GOT leaves it at an address Ghidra made up.
    """
    program = ProgramBuilder()
    program.code(0x1000, ret(), length=1)
    program.function("main", 0x1000)
    program.import_("getline", 0x3000, symbol="_ZSt7getlineIcSt11char_traitsIcESaIcEE")
    if mapped:
        program.data(".bss", BSS, bytes(cxx.IOS_SIZE), writable=True)
        program.symbol("cin", BSS)
    else:
        program.symbol("cin", EXTERNAL)
        program.data(".got", 0x7000, EXTERNAL.to_bytes(8, "little"))
    return program


def test_the_stream_object_is_where_the_program_looks_for_it() -> None:
    module = lift_export(_program(mapped=True).build()).module
    memory = program_memory(module)
    assert memory.load(BSS, 64) == CXX_IOS_VTABLE
    # Optimized code reads the offset to the basic_ios subobject from before the vtable,
    # then the stream's state at 0x20 past it: zero is "nothing has gone wrong".
    assert memory.load(CXX_IOS_VTABLE + cxx.IOS_VBASE_OFFSET, 64) == 0
    assert memory.load(BSS + cxx.IOS_STATE, 32) == 0
    facet = memory.load(BSS + cxx.IOS_FACET, 64)
    assert facet == CXX_CTYPE
    assert memory.read(facet + cxx.CTYPE_WIDEN_OK, 1) == b"\x01"
    assert memory.read(facet + cxx.CTYPE_WIDEN + ord("\n"), 1) == b"\n"


def test_a_stream_reached_through_the_got_is_redirected() -> None:
    """The entry holds an address outside the image; it is pointed at the object here."""
    module = lift_export(_program(mapped=False).build()).module
    memory = program_memory(module)
    object_at = memory.load(0x7000, 64)
    assert object_at != EXTERNAL
    assert memory.load(object_at, 64) == CXX_IOS_VTABLE
    assert memory.load(object_at + cxx.IOS_FACET, 64) == CXX_CTYPE


def test_a_c_program_with_a_global_named_cout_is_left_alone() -> None:
    program = ProgramBuilder()
    program.code(0x1000, ret(), length=1)
    program.function("main", 0x1000)
    program.import_("puts", 0x3000)
    program.data(".bss", BSS, bytes(64), writable=True)
    program.symbol("cout", BSS)
    memory = program_memory(lift_export(program.build()).module)
    assert memory.load(BSS, 64) == 0

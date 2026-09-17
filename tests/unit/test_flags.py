from __future__ import annotations

from ppy_rev.analysis.flags import flag_prefixes
from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import lift_export
from support.exports import ProgramBuilder, const, op, reg, ret


def _module(*strings: bytes) -> Module:
    program = ProgramBuilder()
    for index, text in enumerate(strings):
        program.data(f"data{index}", 0x5000 + 0x200 * index, text + b"\0")
    program.code(0x1000, [op("COPY", [const(0, 8)], reg("RAX"))])
    program.code(0x1004, ret(), length=1)
    program.function("main", 0x1000)
    return lift_export(program.build()).module


def test_flag_prefixes_come_from_readable_strings() -> None:
    module = _module(b"actf{this_is_the_flag}", b"wrong, try again", b"usage: %s KEY")
    assert flag_prefixes(module) == ["actf{"]


def test_a_brace_without_a_flag_word_is_not_a_prefix() -> None:
    module = _module(b"{}", b"%d items", b"struct { int x; }")
    assert flag_prefixes(module) == []

"""Outcomes found by their shape: an output the input decides the program reaches."""

from __future__ import annotations

from ppy_rev.analysis.goals import printing_functions
from ppy_rev.analysis.outcomes import input_dependent_outputs
from ppy_rev.analysis.program import find_main, reachable_functions
from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import lift_export
from support.exports import ProgramBuilder, call, const, op, ram, reg, ret

GETCHAR = 0x3000
PUTCHAR = 0x3010


def _sites(program: ProgramBuilder) -> list[tuple[int, tuple[int, ...], bool, bool]]:
    module: Module = lift_export(program.build()).module
    main = find_main(module)
    found = input_dependent_outputs(
        module, reachable_functions(module, main), printing_functions(module)
    )
    return [(item.address, item.decisions, item.prints_input, item.ends_well) for item in found]


def _checker(*, gate: bool) -> ProgramBuilder:
    """`c = getchar(); if (c == 'a') putchar('!'); return 0;`, or the print without the test."""
    program = ProgramBuilder()
    program.import_("getchar", GETCHAR)
    program.import_("putchar", PUTCHAR)
    program.code(0x1000, call(GETCHAR, 0x1004))
    decide = (
        [
            op("INT_EQUAL", [reg("RAX"), const(0x61, 8)], reg("ZF")),
            op("CBRANCH", [ram(0x1010), reg("ZF")]),
        ]
        if gate
        else [op("BRANCH", [ram(0x1010)])]
    )
    program.code(0x1004, decide)
    program.code(0x1008, [op("COPY", [const(1, 8)], reg("RAX"))])
    program.code(0x100C, ret(), length=1)
    program.code(0x1010, [op("COPY", [const(0x21, 8)], reg("RDI"))])
    program.code(0x1014, call(PUTCHAR, 0x1018))
    program.code(0x1018, [op("COPY", [const(0, 8)], reg("RAX"))])
    program.code(0x101C, ret(), length=1)
    program.function("main", 0x1000)
    return program


def test_an_output_the_input_decides_is_an_outcome() -> None:
    """The message says nothing — `putchar('!')` — but the branch on the input does."""
    found = {address: item for address, *item in _sites(_checker(gate=True))}
    decisions, prints_input, ends_well = found[0x1014]
    assert decisions == (0x1004,)
    assert not prints_input  # the character is a constant: reaching it is what matters
    assert ends_well  # main returns zero from there


def test_leaving_well_is_an_outcome_when_nothing_is_printed() -> None:
    """Plenty of checkers say nothing at all: passing is leaving with a zero status."""
    found = {address: item for address, *item in _sites(_checker(gate=True))}
    returning = [address for address in found if address != 0x1014]
    assert returning, "the return of zero the input decides is an outcome of its own"
    assert found[returning[0]][0] == (0x1004,)


def test_an_output_every_run_makes_is_not_one() -> None:
    """Without a test on the input, printing says nothing about what the program wants."""
    assert _sites(_checker(gate=False)) == []


def test_printing_what_the_input_became() -> None:
    """A program spelling out what it worked out: what it prints came from the input."""
    program = ProgramBuilder()
    program.import_("getchar", GETCHAR)
    program.import_("putchar", PUTCHAR)
    program.code(0x1000, call(GETCHAR, 0x1004))
    program.code(
        0x1004,
        [
            op("INT_ADD", [reg("RAX"), const(1, 8)], reg("RCX")),
            op("INT_EQUAL", [reg("RCX"), const(0, 8)], reg("ZF")),
            op("CBRANCH", [ram(0x1018), reg("ZF")]),
        ],
    )
    program.code(0x1008, [op("COPY", [reg("RCX")], reg("RDI"))])
    program.code(0x100C, call(PUTCHAR, 0x1010))
    program.code(0x1010, [op("BRANCH", [ram(0x1004)])])
    program.code(0x1018, ret(), length=1)
    program.function("main", 0x1000)
    (site,) = _sites(program)
    address, decisions, prints_input, _ = site
    assert address == 0x100C
    assert prints_input
    assert decisions == (0x1004,)


def test_nothing_is_claimed_when_the_input_decides_nothing() -> None:
    program = ProgramBuilder()
    program.import_("putchar", PUTCHAR)
    program.code(0x1000, [op("COPY", [const(0x21, 8)], reg("RDI"))])
    program.code(0x1004, call(PUTCHAR, 0x1008))
    program.code(0x1008, ret(), length=1)
    program.function("main", 0x1000)
    assert _sites(program) == []

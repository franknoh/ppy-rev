from __future__ import annotations

from ppy_rev.analysis.goals import (
    Outcome,
    printing_functions,
    rank_goals,
    sibling_successes,
)
from ppy_rev.analysis.program import StringReference, reachable_functions, string_references
from ppy_rev.analysis.strings import describe_messages, printed_messages_from
from ppy_rev.lift.lifter import lift_export
from support.exports import ProgramBuilder, call, const, op, ram, reg, ret


def _reference(text: bytes, address: int, call: str | None = "puts") -> StringReference:
    register = None if call is None else "RDI"
    return StringReference(
        text, address, "main", address + 0x1000, call, register, external=call is not None
    )


def test_success_and_failure_strings_are_ranked_with_evidence() -> None:
    ranked = rank_goals(
        [
            _reference(b"Enter the key:", 0x10),
            _reference(b"Incorrect key", 0x20),
            _reference(b"Correct!", 0x30),
            _reference(b"usage: check <key>", 0x40, call=None),
        ]
    )
    assert [(candidate.text, candidate.outcome) for candidate in ranked] == [
        ("Incorrect key", Outcome.FAILURE),
        ("Correct!", Outcome.SUCCESS),
        ("usage: check <key>", Outcome.FAILURE),
    ]
    correct = ranked[1]
    assert correct.confidence == 0.95
    assert correct.evidence == (
        "string 'Correct!' contains 'correct'",
        "passed to puts",
        "referenced once",
    )
    assert (correct.address, correct.register, correct.string_address) == (0x1030, "RDI", 0x30)
    usage = ranked[2]
    assert usage.register is None and usage.string_address is None


def test_strings_used_more_than_once_are_less_certain() -> None:
    once = rank_goals([_reference(b"Access granted", 0x10)])
    twice = rank_goals([_reference(b"Access granted", 0x10), _reference(b"Access granted", 0x10)])
    assert once[0].confidence > twice[0].confidence


def test_short_verdict_words() -> None:
    ranked = rank_goals([_reference(b"Granted", 0x10), _reference(b"Rejected", 0x20)])
    assert [(candidate.text, candidate.outcome) for candidate in ranked] == [
        ("Granted", Outcome.SUCCESS),
        ("Rejected", Outcome.FAILURE),
    ]


def test_activation_and_cheers() -> None:
    ranked = rank_goals(
        [
            _reference(b"Thank you - product activated!", 0x10),
            _reference(b"Product activation failure %d\n", 0x20, call="printf"),
            _reference(b"YAYY : %s", 0x30, call="printf"),
        ]
    )
    outcomes = {candidate.text: candidate.outcome for candidate in ranked}
    assert outcomes == {
        "Thank you - product activated!": Outcome.SUCCESS,
        "Product activation failure %d\n": Outcome.FAILURE,
        "YAYY : %s": Outcome.SUCCESS,
    }


def test_prompts_and_negations_are_not_success() -> None:
    ranked = rank_goals(
        [
            _reference(b"Enter your flag: ", 0x10, call="printf"),
            _reference(b"What was the flag again?", 0x20),
            _reference(b"Guess my flag!!\n", 0x30),
            _reference(b"That's not a valid solution you silly goose!", 0x40),
            _reference(b"Hash mismatch :(", 0x50),
            _reference(b"Hash matched!", 0x60),
            _reference(b"Congratulations! Here is your flag:\n", 0x70),
            _reference(b"flag.txt", 0x80, call="fopen"),
        ]
    )
    outcomes = {candidate.text: candidate.outcome for candidate in ranked}
    assert outcomes == {
        "That's not a valid solution you silly goose!": Outcome.FAILURE,
        "Hash mismatch :(": Outcome.FAILURE,
        "Hash matched!": Outcome.SUCCESS,
        "Congratulations! Here is your flag:\n": Outcome.SUCCESS,
    }


def test_what_a_program_prints_is_listed_for_a_manual_goal() -> None:
    """With nothing ranked, the messages and their addresses are what the user needs."""
    references = [
        StringReference(b"Enter the code: ", 0x5000, "main", 0x1100, "puts", "RDI"),
        StringReference(b"The joker settles the pack.", 0x5020, "main", 0x1200, "puts", "RDI"),
        StringReference(b"/etc/passwd", 0x5040, "main", 0x1300, "fopen", "RDI", external=True),
    ]
    assert not [item for item in rank_goals(references) if item.outcome is Outcome.SUCCESS]
    listed = printed_messages_from(references)
    assert listed == ((0x1100, "Enter the code: "), (0x1200, "The joker settles the pack."))
    assert "0x1200" in describe_messages(listed)


def test_a_message_passed_to_something_that_never_prints_is_not_a_verdict() -> None:
    """A table with no terminator reads as the literal after it.

    `expected[i]` then looks like a reference to "Denied", and avoiding the instruction
    that indexes the table would cut the very loop the answer runs through.
    """
    table = StringReference(
        b"\x3b\x29.i'Denied\n", 0x50, "main", 0x1050, "operator[]", "RSI", external=False
    )
    printed = StringReference(b"Denied\n", 0x58, "main", 0x1060, "report", "RDI", external=False)
    ranked = rank_goals([table, printed], printing=frozenset({"report"}))
    assert [candidate.address for candidate in ranked] == [0x1060]
    assert rank_goals([table, printed]) == []


def test_a_message_printed_through_a_helper_is_still_a_verdict() -> None:
    reference = StringReference(b"Correct!", 0x60, "main", 0x1070, "say", "RDI", external=False)
    (candidate,) = rank_goals([reference], printing=frozenset({"say"}))
    assert candidate.outcome is Outcome.SUCCESS


def test_a_printed_flag_is_the_outcome() -> None:
    """A program that prints `ctf{...}` has already decided, whatever words surround it."""
    (candidate,) = rank_goals([_reference(b"here you go: bkctf{s0_c00l}\n", 0x70)])
    assert candidate.outcome is Outcome.SUCCESS
    assert candidate.confidence >= 0.95
    assert "bkctf{s0_c00l}" in candidate.evidence[0]


def test_words_a_challenge_actually_uses() -> None:
    for message in (b"Yippee :3", b"Bingo!", b"you did it", b"That's right", b"pretty good"):
        (candidate,) = rank_goals([_reference(message, 0x80)])
        assert candidate.outcome is Outcome.SUCCESS, message


SIBLING_PUTS = 0x3000
SIBLING_DATA = 0x5000


def _sibling_program() -> ProgramBuilder:
    """`if (input) puts("Ganbatte") else puts("Wrong")`, in p-code."""
    program = ProgramBuilder()
    program.import_("puts", SIBLING_PUTS)
    program.data(".rodata", SIBLING_DATA, b"Wrong\0Ganbatte\0")
    after = program.code(
        0x1000,
        [
            op("INT_EQUAL", [reg("RDI"), const(0, 8)], reg("ZF")),
            op("CBRANCH", [ram(0x1020), reg("ZF")]),
        ],
    )
    program.code(after, [op("COPY", [const(SIBLING_DATA, 8)], reg("RDI"))])
    program.code(after + 4, call(SIBLING_PUTS, 0x1030))
    program.code(0x1020, [op("COPY", [const(SIBLING_DATA + 6, 8)], reg("RDI"))])
    program.code(0x1024, call(SIBLING_PUTS, 0x1030))
    program.code(0x1030, ret(), length=1)
    program.function("main", 0x1000)
    return program


def test_the_other_side_of_a_branch_says_which_message_is_the_verdict() -> None:
    """A challenge may answer in its own words; the branch still says which is which."""
    module = lift_export(_sibling_program().build()).module
    main = module.function_named("main")
    assert main is not None
    reachable = reachable_functions(module, main)
    references = string_references(module, reachable)
    ranked = rank_goals(references, printing_functions(module))
    assert [c.text for c in ranked] == ["Wrong"]

    (found,) = sibling_successes(module, reachable, ranked, references)
    assert found.outcome is Outcome.SUCCESS
    assert found.text == "Ganbatte"
    assert "prints a failure" in found.evidence[1]


def test_no_verdict_on_either_side_invents_nothing() -> None:
    program = _sibling_program()
    program.blocks = [block for block in program.blocks if block.name != ".rodata"]
    program.data(".rodata", SIBLING_DATA, b"left\0right\0")
    module = lift_export(program.build()).module
    main = module.function_named("main")
    assert main is not None
    reachable = reachable_functions(module, main)
    references = string_references(module, reachable)
    ranked = rank_goals(references, printing_functions(module))
    assert sibling_successes(module, reachable, ranked, references) == []

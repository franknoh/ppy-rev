from __future__ import annotations

from ppy_rev.analysis.goals import Outcome, rank_goals
from ppy_rev.analysis.program import StringReference
from ppy_rev.analysis.strings import describe_messages, printed_messages_from


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

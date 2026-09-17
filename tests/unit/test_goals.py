from __future__ import annotations

from ppy_rev.analysis.goals import Outcome, rank_goals
from ppy_rev.analysis.program import StringReference


def _reference(text: bytes, address: int, call: str | None = "puts") -> StringReference:
    register = None if call is None else "RDI"
    return StringReference(text, address, "main", address + 0x1000, call, register)


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

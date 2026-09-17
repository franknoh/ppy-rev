"""Ranking likely success and failure outcomes from the strings a program prints.

Keywords are evidence, not truth: every candidate carries a confidence and the facts
behind it, and the caller can always name a goal or avoid address explicitly.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

from ppy_rev.analysis.program import StringReference

_SUCCESS = (
    (re.compile(r"\bcorrect\b"), 0.9),
    (re.compile(r"\bcongrat"), 0.95),
    (re.compile(r"\bsuccess"), 0.9),
    (re.compile(r"\baccess granted\b"), 0.95),
    (re.compile(r"\bwell done\b"), 0.9),
    (re.compile(r"\bgood job\b"), 0.9),
    (re.compile(r"\byou (win|won|got it)\b"), 0.9),
    (re.compile(r"\bvalid\b"), 0.75),
    (re.compile(r"\baccepted\b"), 0.85),
    (re.compile(r"\bgranted\b"), 0.85),
    (re.compile(r"\bflag\b"), 0.7),
    (re.compile(r"\b(unlocked|solved|passed|activated|registered)\b"), 0.75),
    (re.compile(r"\b(matched|how did (you|u))\b"), 0.75),
    (re.compile(r"\byay+\b"), 0.8),
    (re.compile(r"\b(nice|great|yes|right)\b"), 0.6),
)
_FAILURE = (
    (re.compile(r"\bwrong\b"), 0.9),
    (re.compile(r"\bincorrect\b|\bnot correct\b"), 0.95),
    (re.compile(r"\binvalid\b"), 0.9),
    (re.compile(r"\bfail"), 0.9),
    (re.compile(r"\bnope\b"), 0.9),
    (re.compile(r"\brejected\b"), 0.85),
    (re.compile(r"\btry again\b"), 0.9),
    (re.compile(r"\b(not quite|mismatch)"), 0.9),
    (re.compile(r"\btoo (short|long|big|small)\b|\b(wrong|different) length\b"), 0.85),
    (re.compile(r"\b(access )?denied\b"), 0.9),
    (re.compile(r"\b(bad|sorry|lose|loser)\b"), 0.7),
    (re.compile(r"\busage\b"), 0.6),
    (re.compile(r"\berror\b"), 0.6),
)
_OUTPUT_FUNCTIONS = frozenset(
    {"puts", "printf", "__printf_chk", "fputs", "fwrite", "write", "fprintf", "__fprintf_chk"}
)
_PROMPT = re.compile(
    r"^\W*(enter|input|give me|gimme|guess|type|provide|tell me|what|please (enter|input|type|"
    r"provide|give))\b|\?\W*$"
)
"""Asks for input: printed before the answer exists, so never a verdict on it."""
_NEGATED = re.compile(
    r"\b(not|isn't|isnt|aren't|wasn't|never)\s+(a |an |the |quite |really |very )?"
    r"(valid|correct|right|good|accepted|it|there|the flag)\b"
)


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


@dataclass(frozen=True, slots=True)
class GoalCandidate:
    address: int
    outcome: Outcome
    text: str
    function: str
    confidence: float
    evidence: tuple[str, ...]
    register: str | None = None
    """When set, the outcome is the call at `address` running with this register holding
    `string_address`, not merely reaching the call."""
    string_address: int | None = None
    call: str | None = None


def _score(text: str, patterns: tuple[tuple[re.Pattern[str], float], ...]) -> tuple[float, str]:
    best, reason = 0.0, ""
    for pattern, weight in patterns:
        match = pattern.search(text)
        if match is not None and weight > best:
            best, reason = weight, match.group(0)
    return best, reason


def rank_goals(references: list[StringReference]) -> list[GoalCandidate]:
    """Success and failure candidates, most confident first (ties by address)."""
    counts = Counter(reference.address for reference in references)
    candidates: list[GoalCandidate] = []
    for reference in references:
        if reference.external and reference.call not in _OUTPUT_FUNCTIONS:
            continue  # a file name, a format to scan, a password to compare: not a message
        text = reference.text.decode("latin-1")
        lowered = text.lower()
        success, success_word = _score(lowered, _SUCCESS)
        failure, failure_word = _score(lowered, _FAILURE)
        negated = _NEGATED.search(lowered)
        if negated is not None and failure < 0.9:
            failure, failure_word = 0.9, negated.group(0)
        if _PROMPT.search(lowered.strip()):
            success = 0.0
        if max(success, failure) == 0:
            continue
        outcome = Outcome.SUCCESS if success > failure else Outcome.FAILURE
        confidence = max(success, failure) - 0.5 * min(success, failure)
        keyword = success_word if outcome is Outcome.SUCCESS else failure_word
        evidence = [f"string {text!r} contains {keyword!r}"]
        if reference.call in _OUTPUT_FUNCTIONS:
            confidence += 0.03
            evidence.append(f"passed to {reference.call}")
        if counts[reference.address] == 1:
            confidence += 0.02
            evidence.append("referenced once")
        candidates.append(
            GoalCandidate(
                address=reference.instruction,
                outcome=outcome,
                text=text,
                function=reference.function,
                confidence=round(min(confidence, 0.99), 2),
                evidence=tuple(evidence),
                register=reference.register,
                string_address=reference.address if reference.register is not None else None,
                call=reference.call,
            )
        )
    candidates.sort(key=lambda candidate: (-candidate.confidence, candidate.address))
    return candidates

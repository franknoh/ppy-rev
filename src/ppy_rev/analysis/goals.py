"""Ranking likely success and failure outcomes from the strings a program prints.

Keywords are evidence, not truth: every candidate carries a confidence and the facts
behind it, and the caller can always name a goal or avoid address explicitly.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

from ppy_rev.analysis.outcomes import input_dependent_outputs
from ppy_rev.analysis.program import (
    StringReference,
    callee_addresses,
    calls,
    external_name,
)
from ppy_rev.ir.model import Branch, Function, Module

_SUCCESS = (
    (re.compile(r"\bcorrect\b"), 0.9),
    (re.compile(r"\bcongrat"), 0.95),
    (re.compile(r"\bsuccess|\bsucceeded\b"), 0.9),
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
    (re.compile(r"\b(yippee|bingo|well played|you did it|there it is)\b"), 0.85),
    (re.compile(r"\b(authenticated|welcome back|you'?re in|that'?s (it|right))\b"), 0.8),
    (re.compile(r"\bpretty good\b"), 0.75),
    (re.compile(r"\b(nice|great|yes|right|ok|okay)\b"), 0.6),
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
    (re.compile(r"\b(nah|no way|not today)\b"), 0.85),
    (re.compile(r"\b(bad|sorry|lose|loser)\b"), 0.7),
    (re.compile(r"\busage\b"), 0.6),
    (re.compile(r"\berror\b"), 0.6),
)
_OUTPUT_FUNCTIONS = frozenset(
    {
        "puts",
        "printf",
        "__printf_chk",
        "fputs",
        "fwrite",
        "write",
        "fprintf",
        "__fprintf_chk",
        "std::ostream::operator<<",
    }
)
_PROMPT = re.compile(
    r"^\W*(enter|input|give me|gimme|guess|type|provide|tell me|what|please (enter|input|type|"
    r"provide|give))\b|\?\W*$"
)
"""Asks for input: printed before the answer exists, so never a verdict on it."""
_NEGATED = re.compile(
    r"(?:\b(?:not|never|no)\b|n'?t\b)[^.!?]{0,24}?"
    r"\b(?:valid|correct|right|good|accepted|it|there|quite|the flag)\b"
)
"""A verdict turned around: *"I don't think that's it"* is the failure, not the success.

The words may be a little apart — a program says "that isn't it" and "I don't think
that's it" — so a few words are allowed between, but not a sentence break.
"""


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


_FLAG_SHAPE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,15}\{[^{}]{2,}\}")
"""A flag as challenges write one. A program that prints it has already decided."""


def _score(text: str, patterns: tuple[tuple[re.Pattern[str], float], ...]) -> tuple[float, str]:
    best, reason = 0.0, ""
    for pattern, weight in patterns:
        match = pattern.search(text)
        if match is not None and weight > best:
            best, reason = weight, match.group(0)
    return best, reason


def printing_functions(module: Module) -> frozenset[str]:
    """Names of functions that reach an output call, directly or through other functions.

    A challenge often prints its verdict through a helper of its own, so what a message
    is passed to is only evidence once that callee is followed to a `puts` or an
    `operator<<`.
    """
    callees: dict[str, set[str]] = {}
    prints: set[str] = set()
    for function in module.functions:
        named: set[str] = set()
        for call, _ in calls(function):
            external = external_name(module, call)
            if external is not None:
                if external in _OUTPUT_FUNCTIONS:
                    prints.add(function.name)
                continue
            for address in callee_addresses(call.target):
                callee = module.function_at(address)
                if callee is not None:
                    named.add(callee.name)
        callees[function.name] = named
    growing = True
    while growing:
        growing = False
        for name, named in callees.items():
            if name not in prints and named & prints:
                prints.add(name)
                growing = True
    return frozenset(prints)


def rank_goals(
    references: list[StringReference], printing: frozenset[str] = frozenset()
) -> list[GoalCandidate]:
    """Success and failure candidates, most confident first (ties by address).

    `printing` names the functions that end up printing something; a message passed to a
    call that never prints — `operator[]` on a table that runs into the next literal —
    is not a verdict on the input.
    """
    counts = Counter(reference.address for reference in references)
    candidates: list[GoalCandidate] = []
    for reference in references:
        passed_on = reference.call is not None and reference.call not in _OUTPUT_FUNCTIONS
        if passed_on and (reference.external or reference.call not in printing):
            continue  # a file name, a format to scan, a table index: not a message
        text = reference.text.decode("latin-1")
        lowered = text.lower()
        success, success_word = _score(lowered, _SUCCESS)
        failure, failure_word = _score(lowered, _FAILURE)
        flag = _FLAG_SHAPE.search(text)
        if flag is not None and success < 0.95:
            # Printing the flag itself is the outcome, whatever words surround it.
            success, success_word = 0.95, flag.group(0)
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


_SIBLING_CONFIDENCE = 0.6
"""How much a failure on the other side of a branch is worth without a word of its own."""
_CONFIDENT_FAILURE = 0.85


def sibling_successes(
    module: Module,
    reachable: list[Function],
    ranked: list[GoalCandidate],
    references: list[StringReference],
) -> list[GoalCandidate]:
    """Messages whose branch decides between them and a failure: a verdict with no word.

    `if (ok) print(x) else print("Wrong")` says which of the two is which even when `x`
    holds nothing this would recognize — plenty of challenges answer in their own words,
    or in another language. Only the two blocks the branch goes to are read, because that
    is what makes the pairing evident rather than guessed.
    """
    failures = {
        candidate.address
        for candidate in ranked
        if candidate.outcome is Outcome.FAILURE and candidate.confidence >= _CONFIDENT_FAILURE
    }
    if not failures:
        return []
    already = {candidate.address for candidate in ranked}
    printed = {
        reference.instruction: reference
        for reference in references
        if reference.call in _OUTPUT_FUNCTIONS and reference.instruction not in already
    }
    found: dict[int, GoalCandidate] = {}
    for function in reachable:
        blocks = {block.id: block for block in function.blocks}
        in_block = {
            start.address: block.id for block in function.blocks for start in block.instructions
        }
        for block in function.blocks:
            if not isinstance(block.terminator, Branch):
                continue
            sides = (block.terminator.true_target, block.terminator.false_target)
            if sides[0] == sides[1] or not all(side in blocks for side in sides):
                continue
            fails = [any(in_block.get(address) == side for address in failures) for side in sides]
            if fails[0] == fails[1]:
                continue
            other = sides[1] if fails[0] else sides[0]
            for address, reference in printed.items():
                if in_block.get(address) != other or address in found:
                    continue
                text = reference.text.decode("latin-1")
                if not _says_something(text):
                    continue
                found[address] = GoalCandidate(
                    address=address,
                    outcome=Outcome.SUCCESS,
                    text=text,
                    function=reference.function,
                    confidence=_SIBLING_CONFIDENCE,
                    evidence=(
                        f"string {text!r} holds no verdict of its own",
                        f"the other side of the branch at {block.terminator.origin.address:#x} "
                        "prints a failure",
                        f"passed to {reference.call}",
                    ),
                    register=reference.register,
                    string_address=reference.address if reference.register is not None else None,
                    call=reference.call,
                )
    return sorted(found.values(), key=lambda candidate: candidate.address)


def _says_something(text: str) -> bool:
    """Whether a string is a message rather than a decoration or a bare format.

    Without a verdict word of its own, all this has to go on is the branch it sits on, so
    a `"%s"`, a `"[+] "` or a row of dashes is not enough to call an outcome.
    """
    return sum(character.isalpha() for character in re.sub(r"%[-#0-9.lhz]*[a-zA-Z]", "", text)) >= 3


def shaped_successes(
    module: Module, reachable: list[Function], ranked: list[GoalCandidate]
) -> list[GoalCandidate]:
    """Outputs the input decides the program reaches, for when no message says so.

    This is the last thing tried, and the weakest: it says a program printed something it
    only prints for the right input, not that the message means success. A call that ends
    the program badly is not one; a call that ends it well is a better one.
    """
    already = {candidate.address for candidate in ranked}
    failures = {
        candidate.address
        for candidate in ranked
        if candidate.outcome is Outcome.FAILURE and candidate.confidence >= _CONFIDENT_FAILURE
    }
    found: list[GoalCandidate] = []
    for site in input_dependent_outputs(module, reachable, printing_functions(module)):
        if site.address in already or site.address in failures:
            continue
        if site.ends_badly and not site.ends_well:
            continue
        leaves = site.call in ("exit", "_exit", "return")
        evidence = ["leaves with a success status" if leaves else f"passed to {site.call}"]
        confidence = _SHAPED_CONFIDENCE if site.decisions else _SHOWN_CONFIDENCE
        if site.decisions:
            decided = ", ".join(f"{address:#x}" for address in site.decisions[:3])
            evidence.append(f"reached only through the test on the input at {decided}")
        if site.prints_input:
            confidence += 0.05
            evidence.append("what it prints came from the input")
        if site.ends_well and not site.ends_badly and not leaves:
            confidence += 0.1
            evidence.append("the program then leaves with a success status")
        found.append(
            GoalCandidate(
                address=site.address,
                outcome=Outcome.SUCCESS,
                text="",
                function=site.function,
                confidence=round(confidence, 2),
                evidence=tuple(evidence),
                call=site.call,
            )
        )
    return found


_SHAPED_CONFIDENCE = 0.4
"""What an outcome's shape alone is worth, against 0.9 for a message that says so."""
_SHOWN_CONFIDENCE = 0.3
"""Less again for a call the input only reaches the *contents* of: it may be an echo."""

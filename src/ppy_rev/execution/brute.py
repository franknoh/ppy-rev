"""Brute force: for a small input a solver struggles with, just try every value.

Symbolic execution is defeated by a check that is opaque to it — a hash compared to a
constant, a table the input indexes in a way the solver cannot invert — but when the input
is only a few bytes, running the program on every possible value is faster than reasoning
about it. Each candidate is executed concretely and the goal watch says whether it passed.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass

from ppy_rev.analysis.inputs import InputKind
from ppy_rev.execution.run import Watch, run_program
from ppy_rev.ir.model import Function, Module
from ppy_rev.symbolic.inputs import Charset, charset_values


def charset_bytes(charset: Charset | None) -> tuple[int, ...]:
    """The byte values a charset allows; printable ASCII when none is asked for."""
    return charset_values(charset)


@dataclass(frozen=True, slots=True)
class BruteResult:
    solution: bytes | None
    argv: bytes | None
    stdin: bytes | None
    candidates: int
    reason: str
    """`found`, `exhausted`, `timeout`, `too-large`, or `unsupported-input`."""


def feasible_space(charset: Charset | None, lengths: tuple[int, ...], cap: int) -> bool:
    """Whether every length in `lengths` fits under `cap` candidates together."""
    width = len(charset_bytes(charset))
    total = 0
    for length in lengths:
        total += width**length
        if total > cap:
            return False
    return True


def brute_force(
    module: Module,
    main: Function,
    watches: tuple[Watch, ...],
    kind: InputKind,
    index: int | None,
    lengths: tuple[int, ...],
    charset: Charset | None,
    deadline: float,
    max_candidates: int,
) -> BruteResult:
    """Run every input of the given lengths and charset; return the first to reach the goal.

    Only a single argv argument or stdin is handled — the input a small crackme reads and
    checks whole. `watches` are the goal watch (named "goal") and any avoid watches, exactly
    as verification uses them. The search is bounded by `max_candidates` and by `deadline`
    (monotonic seconds), so a space too large to cover leaves without an answer than hangs.
    """
    if kind not in (InputKind.ARGV, InputKind.STDIN):
        return BruteResult(None, None, None, 0, "unsupported-input")
    alphabet = charset_bytes(charset)
    tried = 0
    for length in lengths:
        for combination in itertools.product(alphabet, repeat=length):
            if tried >= max_candidates:
                return BruteResult(None, None, None, tried, "too-large")
            if tried % 256 == 0 and time.monotonic() > deadline:
                return BruteResult(None, None, None, tried, "timeout")
            tried += 1
            candidate = bytes(combination)
            argv, stdin = _feed(kind, candidate)
            if _reaches(module, main, argv, index, stdin, watches):
                return BruteResult(candidate, argv, stdin, tried, "found")
    return BruteResult(None, None, None, tried, "exhausted")


def _feed(kind: InputKind, candidate: bytes) -> tuple[bytes | None, bytes | None]:
    return (candidate, None) if kind is InputKind.ARGV else (None, candidate)


def _reaches(
    module: Module,
    main: Function,
    argv: bytes | None,
    index: int | None,
    stdin: bytes | None,
    watches: tuple[Watch, ...],
) -> bool:
    reserve = {index: len(argv)} if argv is not None and index is not None else {}
    count = max([0, *reserve]) + 1
    arguments = [f"./{module.name}".encode()] + [b"" for _ in range(1, count)]
    if argv is not None and index is not None:
        arguments[index] = argv
    run = run_program(module, main, arguments, stdin or b"", watches, reserve=reserve)
    return run.first_watch is not None and run.first_watch.name == "goal"

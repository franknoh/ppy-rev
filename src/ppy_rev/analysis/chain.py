"""Recover a staged driver — a binary bomb's phases — so each stage can be solved in turn.

A driver like `main` calls a sequence of stage functions, each consuming one line of input
and sharing a failure sink: `explode_bomb`, a small internal function many phases call that
ends the program. Recovering the ordered stages and the sink lets the solver crack each
stage in isolation (with `--from`) and chain the answers into one input, instead of driving
the whole program through its input parsing at once.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ppy_rev.analysis.inputs import STDIN_READERS
from ppy_rev.analysis.program import (
    callee_addresses,
    calls,
    external_name,
    find_main,
    reachable_functions,
)
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.ir.model import Function, Module

ENDS_PROGRAM = frozenset({"exit", "_exit", "_Exit", "abort", "__stack_chk_fail", "quick_exit"})
"""Library calls that end the process; a function reaching one is a failure sink, not a phase.

Mirrors `analysis.outcomes._LEAVES`; kept here so detection has no private dependency.
"""


@dataclass(frozen=True, slots=True)
class Stage:
    """One phase of a staged driver: the function, and where the driver calls it."""

    name: str
    entry: int
    call_site: int


@dataclass(frozen=True, slots=True)
class ChainPlan:
    """A staged driver: the shared failure sink, the line reader, and the phases in order."""

    sink: int
    sink_name: str
    reader: int | None
    reader_name: str | None
    stages: tuple[Stage, ...]


def _ends_program(module: Module, function: Function) -> bool:
    return any(external_name(module, call) in ENDS_PROGRAM for call, _ in calls(function))


def _reads_stdin(module: Module, function: Function) -> bool:
    return any(external_name(module, call) in STDIN_READERS for call, _ in calls(function))


def _is_reader(module: Module, function: Function) -> bool:
    """Reads a line of input, directly or through a helper.

    A bomb's `read_line` reads through `skip`, which calls `fgets`, so the reader is found
    transitively, not only when the driver's own callee calls `fgets` itself.
    """
    return any(_reads_stdin(module, reached) for reached in reachable_functions(module, function))


def _reaches(module: Module, function: Function, target: int) -> bool:
    return any(reached.entry == target for reached in reachable_functions(module, function))


def _failure_sink(module: Module, reachable: list[Function]) -> int | None:
    """The internal function the most distinct callers reach that itself ends the program.

    `explode_bomb` is called from every phase and from the line reader, and ends the
    program; no ordinary helper has both properties, so caller count plus "ends the
    program" picks it out without needing a symbol named `explode_bomb`.
    """
    callers: dict[int, set[int]] = {}
    for function in reachable:
        for call, _ in calls(function):
            for address in callee_addresses(call.target):
                if module.function_at(address) is not None:
                    callers.setdefault(address, set()).add(function.entry)
    sink: int | None = None
    most = 1  # a shared sink has at least two callers; one caller is just a helper
    for address, callset in callers.items():
        function = module.function_at(address)
        if function is None or not _ends_program(module, function):
            continue
        if len(callset) > most:
            most, sink = len(callset), address
    return sink


def detect_chain(module: Module) -> ChainPlan | None:
    """The staged plan for `module`, or None when it is not a staged driver.

    A staged driver is a `main` that calls, in order, several functions that each reach a
    shared failure sink, interleaved with a stdin line reader. Anything else — a single
    check, a menu, a program with no such sink — returns None, and the caller falls back to
    an ordinary whole-program solve.
    """
    try:
        main = find_main(module)
    except PpyRevError:
        return None
    reachable = reachable_functions(module, main)
    sink = _failure_sink(module, reachable)
    if sink is None:
        return None
    sink_function = module.function_at(sink)
    if sink_function is None:
        return None
    # How many times the driver calls each internal function. A phase is called once, for
    # its own line; the reader and a per-phase helper like `phase_defused` are called once
    # per phase, so counting the calls tells a real phase from the scaffolding around it.
    once = Counter(
        address
        for call, _ in calls(main)
        for address in callee_addresses(call.target)
        if module.function_at(address) is not None
    )
    reader: int | None = None
    reader_name: str | None = None
    stages: list[Stage] = []
    chosen: set[int] = set()
    for call, _ in calls(main):
        for address in callee_addresses(call.target):
            function = module.function_at(address)
            if function is None or address == sink:
                continue
            if _is_reader(module, function):
                if reader is None:
                    reader, reader_name = address, function.name
                continue
            if address in chosen or once[address] != 1:
                continue
            if _reaches(module, function, sink):
                chosen.add(address)
                stages.append(Stage(function.name, address, call.origin.address))
    if not stages:
        return None
    return ChainPlan(sink, sink_function.name, reader, reader_name, tuple(stages))

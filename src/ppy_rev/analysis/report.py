"""A whole-program overview: what `solve` would work with, and why."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ppy_rev.analysis.flags import flag_prefixes
from ppy_rev.analysis.goals import GoalCandidate, Outcome, rank_goals
from ppy_rev.analysis.inputs import InputCandidate, discover_inputs
from ppy_rev.analysis.program import (
    Initializer,
    find_main,
    initializers,
    reachable_functions,
    string_references,
)
from ppy_rev.analysis.reachability import GoalReachability
from ppy_rev.analysis.slicing import backward_slice
from ppy_rev.diagnostics import Diagnostic, PpyRevError
from ppy_rev.ir.model import Module
from ppy_rev.vm.detect import LIKELY_DISPATCHER, Dispatcher, detect_dispatchers


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    name: str
    entry: int
    blocks: int
    operations: int
    reachable: bool
    """Called, directly or not, from main."""
    reaches_goal: bool
    """Can reach the best success candidate."""
    output_only: bool
    """Only produces output, so solving skips calls to it."""


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    target: str
    main: str | None
    functions: tuple[FunctionSummary, ...]
    inputs: tuple[InputCandidate, ...]
    successes: tuple[GoalCandidate, ...]
    failures: tuple[GoalCandidate, ...]
    sliced_operations: int
    flag_formats: tuple[str, ...]
    """Flag shapes the program's own data mentions, such as `actf{`."""
    initializers: tuple[Initializer, ...]
    """Constructors that run before main and are not modeled."""
    dispatchers: tuple[Dispatcher, ...]
    diagnostics: tuple[tuple[str, int], ...]
    """Lifting diagnostic codes in functions reachable from main, with their counts."""


def analyze_module(module: Module, diagnostics: tuple[Diagnostic, ...]) -> AnalysisReport:
    try:
        main = find_main(module)
    except PpyRevError:
        main = None
    reachable = reachable_functions(module, main) if main is not None else []
    reachable_entries = {function.entry for function in reachable}
    ranked = rank_goals(string_references(module, reachable)) if reachable else []
    successes = tuple(item for item in ranked if item.outcome is Outcome.SUCCESS)
    failures = tuple(item for item in ranked if item.outcome is Outcome.FAILURE)
    goal = successes[0] if successes else None
    reachability = GoalReachability(module, frozenset({goal.address})) if goal is not None else None
    protected = frozenset(item.address for item in ranked)
    program_slice = backward_slice(module, protected, None if main is None else main.entry)
    functions = tuple(
        FunctionSummary(
            name=function.name,
            entry=function.entry,
            blocks=len(function.blocks),
            operations=sum(len(block.operations) for block in function.blocks),
            reachable=function.entry in reachable_entries,
            reaches_goal=reachability is not None
            and any(reachability.reaches_goal.get(function.entry, [])),
            output_only=function.entry in program_slice.output_functions,
        )
        for function in module.functions
    )
    names = {function.name for function in reachable}
    counts = Counter(str(item.code) for item in diagnostics if item.location.function in names)
    return AnalysisReport(
        target=f"{module.target.architecture} Linux ELF",
        main=None if main is None else main.name,
        functions=functions,
        inputs=tuple(discover_inputs(module, main)) if main is not None else (),
        successes=successes,
        failures=failures,
        sliced_operations=sum(
            1 for entry, _, _ in program_slice.skipped if entry in reachable_entries
        ),
        flag_formats=tuple(flag_prefixes(module)),
        initializers=initializers(module),
        dispatchers=tuple(
            item for item in detect_dispatchers(module) if item.confidence >= LIKELY_DISPATCHER
        ),
        diagnostics=tuple(sorted(counts.items())),
    )

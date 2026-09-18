"""Concolic search: follow a concrete input, then flip the choices it did not take.

Each run executes the program symbolically but lets the current seed input decide every
branch, so a run is one path and costs no feasibility checks. The choices the seed did not
take are kept as flips: the path condition up to the choice plus the other side. The next
seed is a model of the most promising untried flip, and the search repeats until some run
reaches the goal or no flip is left.

Flips whose other side cannot reach the goal are dropped; the rest are tried deepest
first, preferring code no run has covered yet. This escapes path explosion that
breadth-first symbolic search suffers when many early choices are all feasible.
"""

from __future__ import annotations

import heapq
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from ppy_rev.analysis.reachability import GoalReachability
from ppy_rev.symbolic.executor import Executor, Exploration, Flip
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.state import State


@dataclass(frozen=True, slots=True)
class ConcolicResult:
    exploration: Exploration
    """The last run's exploration: its reached states if the goal was reached."""
    runs: int
    flips: int
    """Flips that were solved into new seeds."""
    exhausted: bool
    """No untried flip was left."""


def concolic_search(
    executor: Executor,
    start: Callable[[], State],
    symbols: list[Expr],
    seed: Mapping[str, int],
    reachability: GoalReachability | None,
    max_runs: int,
    max_seconds: float,
) -> ConcolicResult:
    started = time.monotonic()
    queue: list[tuple[tuple[int, int], int, Flip]] = []
    tried: set[tuple[Expr, ...]] = set()
    seen: set[tuple[tuple[str, int], ...]] = {_key(seed, symbols)}
    current = dict(seed)
    runs = 0
    solved = 0
    counter = 0
    while True:
        executor.seed = current
        executor.flips = []
        executor.phase = f"concolic run {runs + 1}"
        exploration = executor.explore(start())
        runs += 1
        executor.report_progress()
        if exploration.reached:
            executor.seed = None
            return ConcolicResult(exploration, runs, solved, exhausted=False)
        covered = executor.statistics.blocks
        for flip in executor.flips:
            if flip.conditions in tried:
                continue
            tried.add(flip.conditions)
            if (
                reachability is not None
                and flip.location
                and not reachability.can_reach(flip.location)
            ):
                continue
            novel = 0 if flip.location and flip.location[-1] not in covered else 1
            counter += 1
            heapq.heappush(queue, ((novel, -flip.depth), counter, flip))
        found = False
        while queue and not found:
            if runs >= max_runs or time.monotonic() - started > max_seconds:
                break
            _, _, flip = heapq.heappop(queue)
            model = executor.solve_conditions(flip.conditions, symbols)
            if model is None:
                continue
            candidate = {**current, **model}
            key = _key(candidate, symbols)
            if key in seen:
                continue
            seen.add(key)
            solved += 1
            current = candidate
            found = True
        if not found:
            executor.seed = None
            return ConcolicResult(exploration, runs, solved, exhausted=not queue)


def _key(assignment: Mapping[str, int], symbols: list[Expr]) -> tuple[tuple[str, int], ...]:
    return tuple((symbol.name, assignment.get(symbol.name, 0)) for symbol in symbols)

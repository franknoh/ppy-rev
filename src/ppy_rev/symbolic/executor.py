"""Symbolic execution of RevIR.

States run until they fork on a symbolic branch, reach a goal or avoid address, return
from the outermost frame, or stop. Every stop has an explicit reason; semantics RevIR
cannot model and exhausted budgets are reported as incomplete exploration, never as a
path that "does not reach the goal".
"""

from __future__ import annotations

import heapq
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Protocol

from ppy_rev.analysis.locations import Location
from ppy_rev.analysis.reachability import GoalReachability
from ppy_rev.analysis.slicing import Slice
from ppy_rev.diagnostics import DiagnosticCode
from ppy_rev.execution.memory import MemoryFaultError
from ppy_rev.ir.model import (
    DIVISION_OPCODES,
    BinaryOp,
    Block,
    Branch,
    Call,
    Const,
    DirectTarget,
    ExternalTarget,
    Function,
    Halt,
    IndirectJump,
    IndirectTarget,
    Jump,
    Load,
    Module,
    Operand,
    Operation,
    Origin,
    Piece,
    Return,
    Stop,
    Store,
    Subpiece,
    TailCall,
    UnaryOp,
    Unsupported,
    UserOp,
    Var,
)
from ppy_rev.solver.backend import CheckResult, SolverBackend, Status
from ppy_rev.symbolic import encode
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.bounds import unsigned_bounds
from ppy_rev.symbolic.evaluate import UnassignedSymbolError, evaluate
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.regions import MergeRegion, RegionFinder
from ppy_rev.symbolic.state import Constraint, ConstraintKind, Frame, State


class StopReason(StrEnum):
    GOAL = "goal"
    AVOIDED = "avoided"
    RETURNED = "returned"
    EXITED = "exited"
    INFEASIBLE = "infeasible"
    FAULT = "fault"
    UNSUPPORTED = "unsupported"
    BRANCH_BOUND = "branch-bound"
    CALL_DEPTH = "call-depth"
    STEP_BUDGET = "step-budget"
    SOLVER_UNKNOWN = "solver-unknown"


_ENUMERATED_ADDRESSES = 8
"""Addresses a pointer may take before enumerating them costs more than bounding them."""
INCOMPLETE_REASONS = frozenset(
    {
        StopReason.UNSUPPORTED,
        StopReason.BRANCH_BOUND,
        StopReason.CALL_DEPTH,
        StopReason.STEP_BUDGET,
        StopReason.SOLVER_UNKNOWN,
    }
)


@dataclass(frozen=True, slots=True)
class Budget:
    max_states: int = 20_000
    max_steps: int = 20_000_000
    max_call_depth: int = 64
    max_branch_visits: int = 512
    """How often one path may fork at the same branch (bounds symbolic loops)."""
    solver_timeout_ms: int = 30_000
    max_seconds: float = 600.0
    pointer_range: int = 4096
    """Largest address range a symbolic load may cover."""
    store_range: int = 256
    """Largest address range a symbolic store may cover."""
    merge_paths: bool = True
    """Merge the paths of loop-free, call-free branch regions where they join again."""


@dataclass(frozen=True, slots=True)
class Goal:
    addresses: frozenset[int] = frozenset()
    avoid: frozenset[int] = frozenset()
    on_return: Callable[[dict[str, Expr]], Expr] | None = None
    """For solving a single function: the condition its outputs must satisfy."""
    calls: tuple[CallCondition, ...] = ()
    """Reached when one of these calls runs with its register holding the value."""
    avoid_calls: tuple[CallCondition, ...] = ()


@dataclass(frozen=True, slots=True)
class CallCondition:
    address: int
    """The call instruction."""
    register: str
    value: int


@dataclass(frozen=True, slots=True)
class Flip:
    """A choice a seeded run did not take: the path condition up to it and the other side."""

    conditions: tuple[Expr, ...]
    location: tuple[tuple[int, int], ...]
    """(function entry, block) of every frame, where the untaken side would continue."""
    address: int | None
    depth: int
    """Constraints on the path before the choice."""


@dataclass(frozen=True, slots=True)
class Stopped:
    state: State
    reason: StopReason
    detail: str
    function: str | None
    address: int | None
    code: DiagnosticCode | None = None


@dataclass(slots=True)
class Statistics:
    states: int = 0
    steps: int = 0
    forks: int = 0
    solver_calls: int = 0
    stops: Counter[StopReason] = field(default_factory=Counter[StopReason])
    seconds: float = 0.0
    blocks: set[tuple[int, int]] = field(default_factory=set[tuple[int, int]])
    """(function entry, block id) pairs executed by some state."""
    pruned: int = 0
    """States discarded because they could no longer reach the goal."""
    merges: int = 0
    """Paths folded into another path's state at the end of a branch region."""
    hiding_approximations: set[str] = field(default_factory=set[str])
    sliced: int = 0
    """Operations skipped because the backward slice showed they cannot matter."""
    solver_seconds: float = 0.0
    peak_states: int = 0
    """The most states waiting to be explored at once."""
    """Approximations made on some path that may have excluded feasible behaviour."""


@dataclass(slots=True)
class Exploration:
    reached: list[Stopped]
    incomplete: list[Stopped]
    statistics: Statistics
    budget_exhausted: str | None = None
    timed_out: bool = False


@dataclass(frozen=True, slots=True)
class Returned:
    state: State
    outputs: dict[str, Expr]


@dataclass(frozen=True, slots=True)
class Exited:
    state: State
    status: Expr


@dataclass(frozen=True, slots=True)
class Failed:
    state: State
    reason: StopReason
    detail: str


type ExternalOutcome = Returned | Exited | Failed


class ExternalModels(Protocol):
    def call(
        self,
        executor: Executor,
        state: State,
        name: str,
        arguments: dict[str, Expr],
        origin: Origin,
    ) -> list[ExternalOutcome] | None:
        """Model an imported function, or return None when there is no model for `name`."""
        ...


class NoExternals:
    def call(
        self,
        executor: Executor,
        state: State,
        name: str,
        arguments: dict[str, Expr],
        origin: Origin,
    ) -> list[ExternalOutcome] | None:
        del executor, state, name, arguments, origin
        return None


class _Stop(Exception):  # noqa: N818 - internal control flow, never escapes the executor
    def __init__(self, reason: StopReason, detail: str, code: DiagnosticCode | None = None):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.code = code


class Executor:
    def __init__(
        self,
        module: Module,
        backend: SolverBackend,
        goal: Goal,
        externals: ExternalModels | None = None,
        budget: Budget | None = None,
        reachability: GoalReachability | None = None,
        program_slice: Slice | None = None,
    ) -> None:
        self.module = module
        self.slice = program_slice
        self.goal = goal
        self.reachability = reachability
        self.externals = externals or NoExternals()
        self.budget = budget or Budget()
        self.session = backend.session()
        self.statistics = Statistics()
        self._functions = {function.entry: function for function in module.functions}
        self._imports = {
            address: external.name
            for external in module.externals
            for address in external.addresses
        }
        self._stack_pointer = module.target.stack_pointer
        self._pointer_width = module.target.pointer_width
        self._next_state = 0
        self._auxiliary = 0
        self._pending: list[tuple[int, int, State]] = []
        self._regions = RegionFinder()
        self.seed: Mapping[str, int] | None = None
        """When set, runs follow this input instead of forking, recording `flips`."""
        self.flips: list[Flip] = []
        self._started = time.monotonic()
        self._exploration = Exploration([], [], self.statistics)

    # -- public ----------------------------------------------------------------------------

    def new_state_id(self) -> int:
        self._next_state += 1
        self.statistics.states += 1
        return self._next_state

    def renumber(self, state: State) -> None:
        """Give `state` the newest id: among equally deep states it is explored last."""
        self._next_state += 1
        state.id = self._next_state

    def _check(self, assumptions: list[Expr], symbols: Sequence[Expr] = ()) -> CheckResult:
        self.statistics.solver_calls += 1
        started = time.monotonic()
        try:
            return self.session.check(
                assumptions, symbols, timeout_ms=self.budget.solver_timeout_ms
            )
        finally:
            self.statistics.solver_seconds += time.monotonic() - started

    def feasible(self, state: State, extra: list[Expr] | None = None) -> Status:
        return self._check([*state.conditions(), *(extra or [])]).status

    def solve(self, state: State, symbols: list[Expr]) -> dict[str, int] | None:
        return self.solve_with(state, symbols, [])

    def solve_conditions(
        self, conditions: Sequence[Expr], symbols: list[Expr]
    ) -> dict[str, int] | None:
        result = self._check(list(conditions), symbols)
        return dict(result.model) if result.status is Status.SAT else None

    def solve_with(
        self, state: State, symbols: list[Expr], extra: list[Expr]
    ) -> dict[str, int] | None:
        """A model of the path condition plus `extra`, reporting `symbols`."""
        result = self._check([*state.conditions(), *extra], symbols)
        return dict(result.model) if result.status is Status.SAT else None

    def unique_value(self, state: State, value: Expr) -> int | None:
        """The only value `value` can take on this path, or None if it can take several."""
        if value.is_const:
            return value.value
        self._auxiliary += 1
        probe = sx.symbol(f"__probe_{self._auxiliary}", value.width)
        first = self._check([*state.conditions(), sx.equal(probe, value)], [probe])
        if first.status is not Status.SAT:
            return None
        candidate = first.model[probe.name]
        other = sx.bool_not(sx.equal(value, sx.const(candidate, value.width)))
        return candidate if self.feasible(state, [other]) is Status.UNSAT else None

    def explore(self, initial: State, max_reached: int = 1) -> Exploration:
        # Fewest symbolic decisions first: short paths, and short inputs, are found early.
        self._pending = [(initial.decisions, initial.id, initial)]
        self._started = time.monotonic()
        self._exploration = Exploration([], [], self.statistics)
        return self.resume(max_reached)

    def resume(self, max_reached: int) -> Exploration:
        """Continue exploring until `max_reached` goal states are known in total."""
        exploration = self._exploration
        pending = self._pending
        resumed = time.monotonic()
        while pending and len(exploration.reached) < max_reached:
            if self.statistics.states > self.budget.max_states:
                exploration.budget_exhausted = f"more than {self.budget.max_states} states"
                break
            if self.statistics.steps > self.budget.max_steps:
                exploration.budget_exhausted = f"more than {self.budget.max_steps} operations"
                break
            if time.monotonic() - self._started > self.budget.max_seconds:
                exploration.budget_exhausted = f"more than {self.budget.max_seconds:g}s"
                exploration.timed_out = True
                break
            _, _, state = heapq.heappop(pending)
            successors, stopped = self._run(state)
            for successor in successors:
                heapq.heappush(pending, (successor.decisions, successor.id, successor))
            self.statistics.peak_states = max(self.statistics.peak_states, len(pending))
            for stop in stopped:
                self.statistics.stops[stop.reason] += 1
                if stop.reason is StopReason.GOAL:
                    exploration.reached.append(stop)
                elif stop.reason in INCOMPLETE_REASONS:
                    exploration.incomplete.append(stop)
        self.statistics.seconds += time.monotonic() - resumed
        return exploration

    @property
    def exhausted(self) -> bool:
        """No states remain to explore."""
        return not self._pending

    # -- running a state -------------------------------------------------------------------

    def _run(self, state: State) -> tuple[list[State], list[Stopped]]:
        """Advance until the state forks or stops."""
        try:
            while True:
                successors = self._step(state)
                if successors is None:
                    continue
                return successors
        except _Stop as stop:
            stopped = self._stopped(state, stop.reason, stop.detail)
            return [], [replace(stopped, code=stop.code)]

    def _step(self, state: State) -> tuple[list[State], list[Stopped]] | None:
        frame = state.frame
        function = frame.function
        block = function.blocks[frame.block]
        if frame.position == 0:
            self.statistics.blocks.add((function.entry, block.id))
        if frame.position <= len(block.operations):
            for start in block.instructions:
                if start.position == frame.position:
                    outcome = self._observe(state, start.address)
                    if outcome is not None:
                        return outcome
        if frame.position < len(block.operations):
            operation = block.operations[frame.position]
            frame.position += 1
            state.steps += 1
            self.statistics.steps += 1
            if (
                self.slice is not None
                and not isinstance(operation, Call)
                and self.slice.skips(function.entry, block.id, frame.position - 1)
            ):
                self.statistics.sliced += 1
                return None
            return self._operation(state, frame, operation)
        if frame.position == len(block.operations):
            frame.position += 1
            return self._terminator(state, frame, block)
        # A tail call has completed; return its results to our own caller.
        terminator = block.terminator
        if not isinstance(terminator, TailCall):
            raise AssertionError("resumed past the end of a block")
        return self._return(state, frame, terminator.values, None, terminator.origin)

    def _observe(self, state: State, address: int) -> tuple[list[State], list[Stopped]] | None:
        if address in self.goal.avoid:
            return [], [self._stopped(state, StopReason.AVOIDED, f"reached {address:#x}")]
        if address in self.goal.addresses:
            return [], [self._stopped(state, StopReason.GOAL, f"reached {address:#x}", address)]
        return None

    def _stopped(
        self, state: State, reason: StopReason, detail: str, address: int | None = None
    ) -> Stopped:
        frame = state.frames[-1] if state.frames else None
        return Stopped(
            state,
            reason,
            detail,
            None if frame is None else frame.function.name,
            address if address is not None or frame is None else _address(frame.function, frame),
        )

    # -- operations ------------------------------------------------------------------------

    def value(self, frame: Frame, operand: Operand) -> Expr:
        if isinstance(operand, Const):
            return sx.const(operand.value, operand.width)
        found = frame.values.get(operand.id)
        if found is None:
            raise _Stop(
                StopReason.UNSUPPORTED,
                f"v{operand.id} in {frame.function.name} has no value (was it sliced away?)",
            )
        return found

    def _operation(
        self, state: State, frame: Frame, operation: Operation
    ) -> tuple[list[State], list[Stopped]] | None:
        values = frame.values
        match operation:
            case BinaryOp(opcode=opcode, output=output, left=left, right=right):
                left_value, right_value = self.value(frame, left), self.value(frame, right)
                if opcode in DIVISION_OPCODES:
                    self._require_divisor(state, right_value, operation.origin)
                values[output.id] = encode.binary(opcode, left_value, right_value, output.width)
            case UnaryOp(opcode=opcode, output=output, operand=operand):
                values[output.id] = encode.unary(opcode, self.value(frame, operand), output.width)
            case Subpiece(output=output, operand=operand, low_bit=low_bit):
                values[output.id] = encode.subpiece(
                    self.value(frame, operand), low_bit, output.width
                )
            case Piece(output=output, high=high, low=low):
                values[output.id] = encode.piece(self.value(frame, high), self.value(frame, low))
            case Load(output=output, address=address):
                values[output.id] = self.load(
                    state, self.value(frame, address), output.width, operation.origin
                )
            case Store(address=address, value=value):
                self.store(
                    state, self.value(frame, address), self.value(frame, value), operation.origin
                )
            case Call():
                return self._call(state, frame, operation)
            case UserOp():
                raise _Stop(
                    StopReason.UNSUPPORTED,
                    f"user operation {operation.name} has no modeled semantics",
                    DiagnosticCode.UNSUPPORTED_USER_OP,
                )
            case Unsupported():
                raise _Stop(
                    StopReason.UNSUPPORTED, operation.reason, DiagnosticCode.UNSUPPORTED_OPERATION
                )
        return None

    def approximate(self, state: State, note: str, *, may_hide_paths: bool) -> None:
        """Record that a model approximated here.

        Over-approximations (extra behaviour) only risk solutions that fail verification;
        approximations that may exclude behaviour make "no path reaches the goal"
        inconclusive.
        """
        if note not in state.io.approximations:
            state.io.approximations.append(note)
        if may_hide_paths:
            self.statistics.hiding_approximations.add(note)

    def add_constraint(
        self,
        state: State,
        condition: Expr,
        kind: ConstraintKind,
        origin: Origin | None,
        note: str = "",
    ) -> None:
        if condition is sx.TRUE:
            return
        function = state.frames[-1].function.name if state.frames else None
        state.constraints.append(Constraint(condition, kind, function, origin, note))

    def _require_divisor(self, state: State, divisor: Expr, origin: Origin) -> None:
        if divisor.is_const:
            if divisor.value == 0:
                raise _Stop(StopReason.FAULT, f"division by zero at {origin.address:#x}")
            return
        condition = sx.nonzero(divisor)
        self.add_constraint(state, condition, ConstraintKind.DIVISOR, origin)
        if self.feasible(state) is Status.UNSAT:
            raise _Stop(StopReason.FAULT, f"division by zero at {origin.address:#x}")

    # -- memory ----------------------------------------------------------------------------

    def _candidates(
        self, state: State, address: Expr, size: int, write: bool, limit: int
    ) -> list[int]:
        low, high = unsigned_bounds(address)
        if high - low + 1 > limit:
            # Most symbolic pointers have one value, or a handful: asking the solver for
            # them one at a time costs two calls, bounding a 64-bit range costs 128.
            found = self._enumerate(state, address, min(limit, _ENUMERATED_ADDRESSES))
            if found is not None:
                return [
                    candidate
                    for candidate in found
                    if state.memory.accessible(candidate, size, write)
                ]
            concrete = self._seed_value(address) if self.seed is not None else None
            if concrete is not None:
                return self._concretize(state, address, concrete, size, write)
            low, high = self._feasible_bounds(state, address, low, high)
        if high - low + 1 > limit:
            raise _Stop(
                StopReason.UNSUPPORTED,
                f"symbolic pointer {sx.render(address, 120)} ranges over {high - low + 1:#x} "
                f"addresses (limit {limit:#x})",
                DiagnosticCode.SYMBOLIC_POINTER_REQUIRED,
            )
        return [
            candidate
            for candidate in range(low, high + 1)
            if state.memory.accessible(candidate, size, write)
        ]

    def _concretize(
        self, state: State, address: Expr, value: int, size: int, write: bool
    ) -> list[int]:
        """Fix a too-wide symbolic pointer to its value under the seed; flip the choice."""
        fixed = sx.equal(address, sx.const(value, address.width))
        self.flips.append(
            Flip(
                (*state.conditions(), sx.bool_not(fixed)),
                self._locations(state),
                None,
                len(state.constraints),
            )
        )
        self.add_constraint(
            state, fixed, ConstraintKind.POINTER, None, "fixed to its value for the seed input"
        )
        self.approximate(
            state, "a wide symbolic pointer was fixed to its seed value", may_hide_paths=True
        )
        return [value] if state.memory.accessible(value, size, write) else []

    def _enumerate(self, state: State, value: Expr, limit: int) -> list[int] | None:
        """Every value `value` can take on this path, or None if there are more than `limit`."""
        self._auxiliary += 1
        probe = sx.symbol(f"__probe_{self._auxiliary}", value.width)
        binding = sx.equal(probe, value)
        found: list[int] = []
        while len(found) <= limit:
            excluded = [
                sx.bool_not(sx.equal(probe, sx.const(candidate, value.width)))
                for candidate in found
            ]
            result = self._check([*state.conditions(), binding, *excluded], [probe])
            if result.status is Status.UNSAT:
                return sorted(found)
            if result.status is not Status.SAT:
                return None  # undecided: fall back to bounding the range
            found.append(result.model[probe.name])
        return None

    def _feasible_bounds(self, state: State, address: Expr, low: int, high: int) -> tuple[int, int]:
        """Tighten `address`'s range to what the path condition allows, by binary search.

        A check the solver cannot decide counts as feasible, which only widens the range.
        """
        width = address.width

        def possible(condition: Expr) -> bool:
            return self.feasible(state, [condition]) is not Status.UNSAT

        top = high
        while low < top:
            middle = (low + top) // 2
            if possible(sx.unsigned_less_equal(address, sx.const(middle, width))):
                top = middle
            else:
                low = middle + 1
        bottom = low
        while bottom < high:
            middle = (bottom + high + 1) // 2
            if possible(sx.unsigned_less_equal(sx.const(middle, width), address)):
                bottom = middle
            else:
                high = middle - 1
        return low, high

    def _restrict_pointer(
        self, state: State, address: Expr, candidates: list[int], origin: Origin
    ) -> None:
        runs: list[tuple[int, int]] = []
        for candidate in candidates:
            if runs and runs[-1][1] + 1 == candidate:
                runs[-1] = (runs[-1][0], candidate)
            else:
                runs.append((candidate, candidate))
        width = address.width
        condition = sx.bool_or(
            *(
                sx.bool_and(
                    sx.unsigned_less_equal(sx.const(first, width), address),
                    sx.unsigned_less_equal(address, sx.const(last, width)),
                )
                for first, last in runs
            )
        )
        self.add_constraint(state, condition, ConstraintKind.POINTER, origin)
        if self.feasible(state) is Status.UNSAT:
            raise _Stop(StopReason.FAULT, f"symbolic pointer at {origin.address:#x} faults")

    def load(self, state: State, address: Expr, width: int, origin: Origin) -> Expr:
        size = width // 8
        if address.is_const:
            try:
                return state.memory.load(address.value, width)
            except MemoryFaultError as fault:
                raise _Stop(StopReason.FAULT, f"{fault} at {origin.address:#x}") from fault
        candidates = self._candidates(state, address, size, False, self.budget.pointer_range)
        if not candidates:
            raise _Stop(StopReason.FAULT, f"symbolic load at {origin.address:#x} faults")
        self._restrict_pointer(state, address, candidates, origin)
        result = state.memory.load(candidates[-1], width)
        for candidate in reversed(candidates[:-1]):
            result = sx.ite(
                sx.equal(address, sx.const(candidate, address.width)),
                state.memory.load(candidate, width),
                result,
            )
        return result

    def store(self, state: State, address: Expr, value: Expr, origin: Origin) -> None:
        size = value.width // 8
        if address.is_const:
            try:
                state.memory.store(address.value, value)
            except MemoryFaultError as fault:
                raise _Stop(StopReason.FAULT, f"{fault} at {origin.address:#x}") from fault
            return
        candidates = self._candidates(state, address, size, True, self.budget.store_range)
        if not candidates:
            raise _Stop(StopReason.FAULT, f"symbolic store at {origin.address:#x} faults")
        self._restrict_pointer(state, address, candidates, origin)
        for candidate in candidates:
            selected = sx.equal(address, sx.const(candidate, address.width))
            for index in range(size):
                location = candidate + index
                state.memory.write_byte(
                    location,
                    sx.ite(
                        selected,
                        sx.extract(value, index * 8, 8),
                        state.memory.read_byte(location),
                    ),
                )

    # -- calls and returns -----------------------------------------------------------------

    def _call(
        self, state: State, frame: Frame, call: Call, tail: bool = False
    ) -> tuple[list[State], list[Stopped]] | None:
        if (
            not tail
            and self.slice is not None
            and self.slice.skips(frame.function.entry, frame.block, frame.position - 1)
        ):
            # Only output: the call returns, popping its return address, and nothing else.
            # Its other arguments may have been sliced away too, so they are not evaluated,
            # and the slice guarantees no result but the stack pointer is used.
            self.statistics.sliced += 1
            outputs: dict[str, Expr] = {}
            for register, operand in zip(call.argument_registers, call.arguments, strict=True):
                if register == self._stack_pointer:
                    pointer = self.value(frame, operand)
                    outputs[register] = sx.add(
                        pointer, sx.const(self._pointer_width // 8, pointer.width)
                    )
            self._bind_results(frame, call, {}, outputs)
            return None
        arguments = {
            register: self.value(frame, operand)
            for register, operand in zip(call.argument_registers, call.arguments, strict=True)
        }
        reached = self._call_conditions(state, call, arguments)
        try:
            outcome = self._dispatch(state, frame, call, arguments, tail)
        except _Stop as stop:
            if not reached:
                raise
            # The goal states split off above stand on their own.
            stopped = replace(self._stopped(state, stop.reason, stop.detail), code=stop.code)
            return [], [*reached, stopped]
        if not reached:
            return outcome
        if outcome is None:
            return [state], reached
        return outcome[0], outcome[1] + reached

    def _call_conditions(
        self, state: State, call: Call, arguments: dict[str, Expr]
    ) -> list[Stopped]:
        """Split off goal states for goal calls; exclude avoided arguments from this state."""
        reached: list[Stopped] = []
        address = call.origin.address
        for condition in self.goal.avoid_calls:
            holds = self._argument_is(arguments, condition, address)
            if holds is None or holds is sx.FALSE:
                continue
            if holds is sx.TRUE:
                raise _Stop(StopReason.AVOIDED, f"call at {address:#x} prints an avoided message")
            self.add_constraint(state, sx.bool_not(holds), ConstraintKind.GOAL, call.origin)
            if self.feasible(state) is Status.UNSAT:
                raise _Stop(StopReason.AVOIDED, f"call at {address:#x} prints an avoided message")
        for condition in self.goal.calls:
            holds = self._argument_is(arguments, condition, address)
            if holds is None or holds is sx.FALSE:
                continue
            detail = f"call at {address:#x} with {condition.register} = {condition.value:#x}"
            if holds is sx.TRUE:
                raise _Stop(StopReason.GOAL, detail)
            goal_state = state.fork(self.new_state_id())
            self.add_constraint(goal_state, holds, ConstraintKind.GOAL, call.origin)
            if self.feasible(goal_state) is Status.SAT:
                reached.append(self._stopped(goal_state, StopReason.GOAL, detail, address))
            self.add_constraint(state, sx.bool_not(holds), ConstraintKind.GOAL, call.origin)
        return reached

    @staticmethod
    def _argument_is(
        arguments: dict[str, Expr], condition: CallCondition, address: int
    ) -> Expr | None:
        if condition.address != address:
            return None
        value = arguments.get(condition.register)
        if value is None:
            return None
        return sx.equal(value, sx.const(condition.value, value.width))

    def _dispatch(
        self, state: State, frame: Frame, call: Call, arguments: dict[str, Expr], tail: bool
    ) -> tuple[list[State], list[Stopped]] | None:
        address: int
        match call.target:
            case DirectTarget() | ExternalTarget():
                address = call.target.address
            case IndirectTarget():
                target = self.value(frame, call.target.address)
                if not target.is_const:
                    raise _Stop(
                        StopReason.UNSUPPORTED,
                        f"indirect call through {sx.render(target, 120)}",
                        DiagnosticCode.UNRESOLVED_INDIRECT_BRANCH,
                    )
                address = target.value
        callee = self._functions.get(address)
        if callee is not None:
            if len(state.frames) >= self.budget.max_call_depth:
                raise _Stop(
                    StopReason.CALL_DEPTH, f"call depth exceeds {self.budget.max_call_depth}"
                )
            state.frames.append(
                Frame(
                    function=callee,
                    block=0,
                    position=0,
                    values={
                        item.value.id: self._argument(arguments, item.register, callee)
                        for item in callee.inputs
                    },
                    expected_return=frame.expected_return
                    if tail
                    else self._pushed(state, arguments),
                    resume=call,
                    tail=tail,
                )
            )
            return None
        name = self._imports.get(address)
        if name is None:
            raise _Stop(
                StopReason.UNSUPPORTED,
                f"call to {address:#x}, which is neither lifted nor imported",
                DiagnosticCode.UNSUPPORTED_OPERATION,
            )
        before = len(state.constraints)
        prefix = tuple(state.conditions())
        outcomes = self.externals.call(self, state, name, arguments, call.origin)
        if outcomes is None:
            raise _Stop(StopReason.UNSUPPORTED, f"no model for imported function {name}")
        if self.seed is not None and len(outcomes) > 1:
            outcomes = self._seeded_outcomes(outcomes, before, prefix, call.origin.address)
        successors: list[State] = []
        stopped: list[Stopped] = []
        for outcome in outcomes:
            match outcome:
                case Returned(state=successor, outputs=outputs):
                    pointer = outputs.get(self._stack_pointer, arguments.get(self._stack_pointer))
                    if pointer is not None:
                        outputs[self._stack_pointer] = sx.add(
                            pointer, sx.const(self._pointer_width // 8, pointer.width)
                        )
                    self._bind_results(successor.frame, call, arguments, outputs)
                    successors.append(successor)
                case Exited(state=successor, status=status):
                    detail = f"exit({sx.render(status, 80)}) in {name}"
                    stopped.append(self._stopped(successor, StopReason.EXITED, detail))
                case Failed(state=successor, reason=reason, detail=detail):
                    stopped.append(self._stopped(successor, reason, detail))
        if len(successors) == 1 and not stopped and successors[0] is state:
            return None
        return successors, stopped

    def _seeded_outcomes(
        self, outcomes: list[ExternalOutcome], before: int, prefix: tuple[Expr, ...], address: int
    ) -> list[ExternalOutcome]:
        """Of a model's alternatives, the one the seed input selects; the rest become flips."""
        chosen: ExternalOutcome | None = None
        for outcome in outcomes:
            added = tuple(item.condition for item in outcome.state.constraints[before:])
            values = [self._seed_value(condition) for condition in added]
            if chosen is None and all(value == 1 for value in values):
                chosen = outcome
            else:
                location = self._locations(outcome.state) if outcome.state.frames else ()
                self.flips.append(Flip(prefix + added, location, address, len(prefix)))
        return [chosen] if chosen is not None else outcomes

    def _argument(self, arguments: dict[str, Expr], register: str, callee: Function) -> Expr:
        found = arguments.get(register)
        if found is None:
            raise _Stop(
                StopReason.UNSUPPORTED,
                f"call to {callee.name} does not provide register {register}",
            )
        return found

    def _pushed(self, state: State, arguments: dict[str, Expr]) -> Expr | None:
        pointer = arguments.get(self._stack_pointer)
        if pointer is None or not pointer.is_const:
            return None
        try:
            return state.memory.load(pointer.value, self._pointer_width)
        except MemoryFaultError:
            return None

    def _bind_results(
        self, frame: Frame, call: Call, arguments: dict[str, Expr], outputs: dict[str, Expr]
    ) -> None:
        for register, result in zip(call.result_registers, call.results, strict=True):
            produced = outputs.get(register, arguments.get(register))
            if produced is None:
                # A register an import clobbers without a modeled value: unknown, not zero.
                self._auxiliary += 1
                name = f"__clobbered_{register}_{call.origin.address:x}_{self._auxiliary}"
                produced = sx.symbol(name, result.width)
            frame.values[result.id] = _resize(produced, result.width)

    def _return(
        self,
        state: State,
        frame: Frame,
        values: tuple[Operand, ...],
        return_address: Operand | None,
        origin: Origin,
    ) -> tuple[list[State], list[Stopped]] | None:
        outermost = len(state.frames) == 1
        outputs = {
            register: self.value(frame, value)
            for register, value in zip(frame.function.output_registers, values, strict=True)
            # What the outermost function returns may have been sliced away as irrelevant.
            if not (outermost and isinstance(value, Var) and value.id not in frame.values)
        }
        if return_address is not None and frame.expected_return is not None:
            actual = self.value(frame, return_address)
            match_condition = sx.equal(actual, frame.expected_return)
            if match_condition is sx.FALSE:
                raise _Stop(
                    StopReason.FAULT,
                    f"{frame.function.name} returns to {sx.render(actual, 80)}, "
                    f"not {sx.render(frame.expected_return, 80)}",
                )
            self.add_constraint(state, match_condition, ConstraintKind.RETURN_ADDRESS, origin)
        state.frames.pop()
        if not state.frames:
            state.outputs = outputs
            if self.goal.on_return is not None:
                condition = self.goal.on_return(outputs)
                self.add_constraint(state, condition, ConstraintKind.GOAL, origin)
                status = self.feasible(state)
                if status is Status.SAT:
                    return [], [self._stopped(state, StopReason.GOAL, "returned", origin.address)]
                if status is not Status.UNSAT:
                    return [], [self._stopped(state, StopReason.SOLVER_UNKNOWN, str(status))]
            return [], [self._stopped(state, StopReason.RETURNED, "outermost function returned")]
        caller = state.frame
        call = frame.resume
        if call is None:
            raise AssertionError("inner frame without a call to resume")
        arguments = {
            register: self.value(caller, operand)
            for register, operand in zip(call.argument_registers, call.arguments, strict=True)
        }
        self._bind_results(caller, call, arguments, outputs)
        return None

    # -- control flow ----------------------------------------------------------------------

    def _transfer(self, frame: Frame, source: int, target: int) -> None:
        block = frame.function.blocks[target]
        if block.phis:
            updates = [
                (phi.output.id, self.value(frame, dict(phi.incoming)[source])) for phi in block.phis
            ]
            for identifier, value in updates:
                frame.values[identifier] = value
        frame.block = target
        frame.position = 0

    def _terminator(
        self, state: State, frame: Frame, block: Block
    ) -> tuple[list[State], list[Stopped]] | None:
        terminator = block.terminator
        match terminator:
            case Jump():
                self._transfer(frame, block.id, terminator.target)
                return None
            case Branch():
                condition = sx.nonzero(self.value(frame, terminator.condition))
                if condition.is_const:
                    target = terminator.true_target if condition.value else terminator.false_target
                    self._transfer(frame, block.id, target)
                    return None
                choices = [
                    (condition, terminator.true_target),
                    (sx.bool_not(condition), terminator.false_target),
                ]
                region = (
                    self._regions.region(frame.function, block.id)
                    if self.budget.merge_paths and self.seed is None
                    else None
                )
                if region is not None:
                    return self._fork_and_merge(state, choices, terminator.origin, region)
                return self._fork(state, choices, terminator.origin)
            case IndirectJump():
                target = self.value(frame, terminator.address)
                if target.is_const:
                    block_id = dict(terminator.targets).get(target.value)
                    if block_id is None:
                        raise _Stop(
                            StopReason.UNSUPPORTED,
                            f"indirect jump to unrecovered target {target.value:#x}",
                            DiagnosticCode.UNRESOLVED_INDIRECT_BRANCH,
                        )
                    self._transfer(frame, block.id, block_id)
                    return None
                choices = [
                    (sx.equal(target, sx.const(address, target.width)), block_id)
                    for address, block_id in terminator.targets
                ]
                known = sx.bool_or(*(condition for condition, _ in choices))
                if self.feasible(state, [sx.bool_not(known)]) is not Status.UNSAT:
                    raise _Stop(
                        StopReason.UNSUPPORTED,
                        f"indirect jump at {terminator.origin.address:#x} may leave its "
                        "recovered targets",
                        DiagnosticCode.UNRESOLVED_INDIRECT_BRANCH,
                    )
                return self._fork(state, choices, terminator.origin)
            case Return():
                return self._return(
                    state, frame, terminator.values, terminator.return_address, terminator.origin
                )
            case TailCall():
                return self._call(state, frame, terminator.call, tail=True)
            case Halt():
                raise _Stop(StopReason.FAULT, "a non-returning call returned")
            case Stop():
                raise _Stop(
                    StopReason.UNSUPPORTED, terminator.reason, DiagnosticCode.MISSING_INSTRUCTION
                )

    def _fork(
        self, state: State, choices: list[tuple[Expr, int]], origin: Origin
    ) -> tuple[list[State], list[Stopped]]:
        frame = state.frame
        site = (frame.function.entry, frame.block)
        visits = state.branch_counts.get(site, 0) + 1
        state.branch_counts[site] = visits
        if visits > self.budget.max_branch_visits:
            raise _Stop(
                StopReason.BRANCH_BOUND,
                f"branch at {origin.address:#x} forked more than "
                f"{self.budget.max_branch_visits} times on one path",
            )
        if self.seed is not None:
            followed = self._follow_seed(state, choices, origin)
            if followed is not None:
                return followed
        source = frame.block
        successors: list[State] = []
        stopped: list[Stopped] = []
        unsatisfiable = 0
        for index, (condition, target) in enumerate(choices):
            last = index == len(choices) - 1
            child = state if last else state.fork(self.new_state_id())
            self.add_constraint(child, condition, ConstraintKind.BRANCH, origin)
            if last and unsatisfiable == len(choices) - 1:
                status = Status.SAT  # the parent was feasible and every other side was not
            else:
                status = self.feasible(child)
            if status is Status.UNSAT:
                unsatisfiable += 1
                self.statistics.stops[StopReason.INFEASIBLE] += 1
                continue
            if status is not Status.SAT:
                stopped.append(self._stopped(child, StopReason.SOLVER_UNKNOWN, str(status)))
                continue
            self._transfer(child.frame, source, target)
            if self.reachability is not None and not self.reachability.can_reach(
                [(frame.function.entry, frame.block) for frame in child.frames]
            ):
                self.statistics.pruned += 1
                continue
            successors.append(child)
        if len(successors) > 1:
            self.statistics.forks += len(successors) - 1
            for successor in successors:
                successor.decisions += 1
        return successors, stopped

    # -- seeded runs -----------------------------------------------------------------------

    def _seed_value(self, expression: Expr) -> int | None:
        if self.seed is None:
            return None
        try:
            return evaluate(expression, self.seed)
        except UnassignedSymbolError:
            return None

    def _locations(self, state: State, block: int | None = None) -> tuple[tuple[int, int], ...]:
        frames = [(frame.function.entry, frame.block) for frame in state.frames]
        if block is not None and frames:
            frames[-1] = (frames[-1][0], block)
        return tuple(frames)

    def _follow_seed(
        self, state: State, choices: list[tuple[Expr, int]], origin: Origin
    ) -> tuple[list[State], list[Stopped]] | None:
        """Take the choice the seed input takes; remember the others as flips.

        Returns None when the seed does not decide the choice (it involves values the
        seed does not assign), so the caller forks as usual.
        """
        values = [self._seed_value(condition) for condition, _ in choices]
        if any(value is None for value in values) or sum(1 for value in values if value) != 1:
            return None
        prefix = tuple(state.conditions())
        for (condition, target), value in zip(choices, values, strict=True):
            if not value:
                self.flips.append(
                    Flip(
                        (*prefix, condition),
                        self._locations(state, target),
                        origin.address,
                        len(prefix),
                    )
                )
        condition, target = next(
            choice for choice, value in zip(choices, values, strict=True) if value
        )
        self.add_constraint(state, condition, ConstraintKind.BRANCH, origin)
        self._transfer(state.frame, state.frame.block, target)
        if self.reachability is not None and not self.reachability.can_reach(
            self._locations(state)
        ):
            self.statistics.pruned += 1
            return [], []
        return [state], []

    # -- merging ---------------------------------------------------------------------------

    def _fork_and_merge(
        self, state: State, choices: list[tuple[Expr, int]], origin: Origin, region: MergeRegion
    ) -> tuple[list[State], list[Stopped]]:
        """Fork, run every path through `region` to its join, and merge the arrivals."""
        depth = len(state.frames)
        shared_constraints = len(state.constraints)
        decisions = state.decisions
        checkpoint = state.memory.checkpoint()
        pending, stopped = self._fork(state, choices, origin)
        arrived: list[State] = []
        escaped: list[State] = []
        while pending:
            current = pending.pop()
            frame = current.frame
            if len(current.frames) == depth and frame.block == region.join and not frame.position:
                arrived.append(current)
                continue
            if (
                len(current.frames) == depth
                and not frame.position
                and frame.block not in region.blocks
            ):
                escaped.append(current)  # left the loop: continues on its own
                continue
            try:
                outcome = self._step(current)
            except _Stop as stop:
                failure = self._stopped(current, stop.reason, stop.detail)
                stopped.append(replace(failure, code=stop.code))
                continue
            if outcome is None:
                pending.append(current)
            else:
                pending.extend(outcome[0])
                stopped.extend(outcome[1])
        if len(arrived) <= 1:
            return arrived + escaped, stopped
        merged = self._merge(arrived, shared_constraints, checkpoint, origin, region.join)
        if merged is None:
            return arrived + escaped, stopped
        merged.decisions = decisions + 1
        return [merged, *escaped], stopped

    def _address_cells(self, state: State) -> set[int]:
        """Bytes of memory the current function loads addresses from, where known now.

        This only steers merging (merged values stay exact), so a slot whose address is not
        known yet is simply not counted.
        """
        frame = state.frame
        cells: set[int] = set()
        for location in self._regions.address_slots(frame.function):
            address = self._resolve_location(state, location)
            if address is not None:
                cells.update(range(address, address + self._pointer_width // 8))
        return cells

    def _resolve_location(self, state: State, location: Location) -> int | None:
        base, offset = location
        match base:
            case ("const", _):
                value = 0
            case ("value", int() as identifier):
                known = state.frame.values.get(identifier)
                if known is None or not known.is_const:
                    return None
                value = known.value
            case ("load", tuple() as inner, int() as width):
                pointer = self._resolve_location(state, inner)
                if pointer is None or not state.memory.accessible(pointer, width // 8, False):
                    return None
                loaded = state.memory.load(pointer, width)
                if not loaded.is_const:
                    return None
                value = loaded.value
            case _:
                return None
        return (value + offset) & ((1 << self._pointer_width) - 1)

    def _merge(
        self,
        states: list[State],
        shared_constraints: int,
        checkpoint: object,
        origin: Origin,
        join: int,
    ) -> State | None:
        """Fold states that forked after `shared_constraints` into the last one.

        Their constraint suffixes are mutually exclusive (each starts with a different
        branch outcome), so each value is an if-then-else chain over those suffixes.
        States that disagree between concrete values used as addresses (a buffer index, an
        interpreter's program counter), or between concrete bytes in memory, are not
        merged: making that state symbolic would turn later memory accesses symbolic.
        """
        selectors = [
            sx.bool_and(*(item.condition for item in current.constraints[shared_constraints:]))
            for current in states
        ]
        merged = states[-1]
        if any(not _same_io(current, merged) for current in states[:-1]):
            return None
        frame_values = [current.frame.values for current in states]
        # Values some path never defined were defined inside the region and cannot be used
        # after its join, which none of those definitions dominate.
        usable = self._regions.usable_after(merged.frame.function, join)
        shared = {
            identifier
            for identifier in set(frame_values[0]).intersection(*frame_values[1:])
            if usable(identifier)
        }
        addressing = self._regions.addressing(merged.frame.function)
        values: dict[int, Expr] = {}
        for identifier in shared:
            candidates = [current[identifier] for current in frame_values]
            choice = _choose(selectors, candidates, identifier not in addressing)
            if choice is None:
                return None
            values[identifier] = choice
        written = set[int]().union(
            *(current.memory.written_since(checkpoint) for current in states)
        )
        bytes_: dict[int, Expr] = {}
        address_cells = self._address_cells(merged)
        for address in sorted(written):
            candidates = [current.memory.read_byte(address) for current in states]
            allowed = address not in address_cells
            choice = _choose(selectors, candidates, allow_constants=allowed)
            if choice is None:
                return None
            bytes_[address] = choice
        self.statistics.merges += len(states) - 1
        merged.frame.values.update(values)
        for address, byte in bytes_.items():
            if byte is not merged.memory.read_byte(address):
                merged.memory.write_byte(address, byte)
        for current in states[:-1]:
            merged.steps = max(merged.steps, current.steps)
            for site, visits in current.branch_counts.items():
                merged.branch_counts[site] = max(merged.branch_counts.get(site, 0), visits)
        del merged.constraints[shared_constraints:]
        self.add_constraint(
            merged,
            sx.bool_or(*selectors),
            ConstraintKind.BRANCH,
            origin,
            f"one of {len(states)} merged paths",
        )
        return merged


def _same_io(first: State, second: State) -> bool:
    one, other = first.io, second.io
    return (
        one.stdin is other.stdin
        and one.stdin_position == other.stdin_position
        and one.stdin_reads == other.stdin_reads
        and one.heap_next == other.heap_next
        and len(one.stdout) == len(other.stdout)
        and all(a is b for a, b in zip(one.stdout, other.stdout, strict=True))
    )


def _choose(selectors: list[Expr], values: list[Expr], allow_constants: bool) -> Expr | None:
    """The if-then-else of `values` by `selectors`.

    None when concrete values disagree and that is not allowed.
    """
    if not allow_constants and len({value.value for value in values if value.is_const}) > 1:
        return None
    result = values[-1]
    for selector, value in zip(reversed(selectors[:-1]), reversed(values[:-1]), strict=True):
        result = sx.ite(selector, value, result)
    return result


def _address(function: Function, frame: Frame) -> int | None:
    block = function.blocks[frame.block]
    position = max(0, frame.position - 1)
    if position < len(block.operations):
        return block.operations[position].origin.address
    return block.terminator.origin.address


def _resize(value: Expr, width: int) -> Expr:
    if value.width == width:
        return value
    if value.width < width:
        return sx.zero_extend(value, width)
    return sx.extract(value, 0, width)

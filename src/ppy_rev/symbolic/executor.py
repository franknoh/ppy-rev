"""Symbolic execution of RevIR.

States run until they fork on a symbolic branch, reach a goal or avoid address, return
from the outermost frame, or stop. Every stop has an explicit reason; semantics RevIR
cannot model and exhausted budgets are reported as incomplete exploration, never as a
path that "does not reach the goal".
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Protocol

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
)
from ppy_rev.solver.backend import SolverBackend, Status
from ppy_rev.symbolic import encode
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.bounds import unsigned_bounds
from ppy_rev.symbolic.expr import Expr
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


@dataclass(frozen=True, slots=True)
class Goal:
    addresses: frozenset[int] = frozenset()
    avoid: frozenset[int] = frozenset()
    on_return: Callable[[dict[str, Expr]], Expr] | None = None
    """For solving a single function: the condition its outputs must satisfy."""


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


@dataclass(slots=True)
class Exploration:
    reached: list[Stopped]
    incomplete: list[Stopped]
    statistics: Statistics
    budget_exhausted: str | None = None


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
    ) -> None:
        self.module = module
        self.goal = goal
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

    # -- public ----------------------------------------------------------------------------

    def new_state_id(self) -> int:
        self._next_state += 1
        self.statistics.states += 1
        return self._next_state

    def feasible(self, state: State, extra: list[Expr] | None = None) -> Status:
        self.statistics.solver_calls += 1
        result = self.session.check(
            [*state.conditions(), *(extra or [])], timeout_ms=self.budget.solver_timeout_ms
        )
        return result.status

    def solve(self, state: State, symbols: list[Expr]) -> dict[str, int] | None:
        self.statistics.solver_calls += 1
        result = self.session.check(
            state.conditions(), symbols, timeout_ms=self.budget.solver_timeout_ms
        )
        return dict(result.model) if result.status is Status.SAT else None

    def explore(self, initial: State, max_reached: int = 1) -> Exploration:
        started = time.monotonic()
        reached: list[Stopped] = []
        incomplete: list[Stopped] = []
        pending: list[State] = [initial]
        exhausted: str | None = None
        while pending:
            if self.statistics.states > self.budget.max_states:
                exhausted = f"more than {self.budget.max_states} states"
                break
            if self.statistics.steps > self.budget.max_steps:
                exhausted = f"more than {self.budget.max_steps} operations"
                break
            if time.monotonic() - started > self.budget.max_seconds:
                exhausted = f"more than {self.budget.max_seconds:g}s"
                break
            state = pending.pop()
            successors, stopped = self._run(state)
            pending.extend(reversed(successors))
            for stop in stopped:
                self.statistics.stops[stop.reason] += 1
                if stop.reason is StopReason.GOAL:
                    reached.append(stop)
                elif stop.reason in INCOMPLETE_REASONS:
                    incomplete.append(stop)
            if len(reached) >= max_reached:
                break
        self.statistics.seconds += time.monotonic() - started
        return Exploration(reached, incomplete, self.statistics, exhausted)

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
        return frame.values[operand.id]

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
        arguments = {
            register: self.value(frame, operand)
            for register, operand in zip(call.argument_registers, call.arguments, strict=True)
        }
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
        outcomes = self.externals.call(self, state, name, arguments, call.origin)
        if outcomes is None:
            raise _Stop(StopReason.UNSUPPORTED, f"no model for imported function {name}")
        successors: list[State] = []
        stopped: list[Stopped] = []
        for outcome in outcomes:
            match outcome:
                case Returned(state=successor, outputs=outputs):
                    pointer = outputs.get(self._stack_pointer)
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
                raise _Stop(StopReason.UNSUPPORTED, f"call result {register} is undefined")
            frame.values[result.id] = _resize(produced, result.width)

    def _return(
        self,
        state: State,
        frame: Frame,
        values: tuple[Operand, ...],
        return_address: Operand | None,
        origin: Origin,
    ) -> tuple[list[State], list[Stopped]] | None:
        outputs = {
            register: self.value(frame, value)
            for register, value in zip(frame.function.output_registers, values, strict=True)
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
                return self._fork(
                    state,
                    [
                        (condition, terminator.true_target),
                        (sx.bool_not(condition), terminator.false_target),
                    ],
                    terminator.origin,
                )
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
            successors.append(child)
        if len(successors) > 1:
            self.statistics.forks += len(successors) - 1
        return successors, stopped


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

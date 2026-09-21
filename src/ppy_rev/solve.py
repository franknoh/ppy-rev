"""Automatic solving: find the input that drives a program to its success outcome."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

from ppy_rev.abi import calling_convention
from ppy_rev.analysis.flags import flag_prefixes
from ppy_rev.analysis.goals import (
    GoalCandidate,
    Outcome,
    printing_functions,
    rank_goals,
    shaped_successes,
    sibling_successes,
)
from ppy_rev.analysis.inputs import InputCandidate, InputKind, discover_inputs
from ppy_rev.analysis.program import (
    executable_address,
    find_main,
    reachable_functions,
    string_references,
)
from ppy_rev.analysis.reachability import GoalReachability
from ppy_rev.analysis.slicing import backward_slice
from ppy_rev.analysis.strings import describe_messages, printed_messages
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.execution.memory import ConcreteMemory
from ppy_rev.execution.program import enter_main, program_memory
from ppy_rev.execution.run import Watch, run_program
from ppy_rev.execution.startup import Initialization, run_initializers
from ppy_rev.ir.model import Function, Module
from ppy_rev.progress import Progress
from ppy_rev.solver.backend import SolverBackend
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.summaries.symbolic import CLOCK_SYMBOL, TRACED_SYMBOL, SymbolicLibc
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.concolic import ConcolicResult, concolic_search
from ppy_rev.symbolic.executor import (
    INCOMPLETE_REASONS,
    Budget,
    CallCondition,
    Executor,
    Exploration,
    Goal,
    Stopped,
    StopReason,
)
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.inputs import (
    NEWLINE,
    Charset,
    argv_constraints,
    argv_solution,
    argv_symbols,
    file_symbols,
    in_charset,
    stdin_constraints,
    stdin_solution,
    stdin_symbols,
)
from ppy_rev.symbolic.memory import SymbolicMemory
from ppy_rev.symbolic.state import ConstraintKind, Frame, State, SymbolicIO
from ppy_rev.verify.sandbox import SandboxOptions, run_sandboxed

DEFAULT_STDIN_LENGTH = 256
DEFAULT_FILE_LENGTH = 64
"""Bytes offered for a file the program reads: a flag, typically."""
PREFERENCE_PATHS = 8
"""Goal paths examined for a printable solution before accepting any bytes."""


@dataclass(frozen=True, slots=True)
class SolveRequest:
    binary: Path
    argv: int | None = None
    """Treat argv[index] as the input (default: discover)."""
    stdin: int | None = None
    """Treat this many bytes of standard input as the input (default: discover)."""
    goal_address: int | None = None
    goal_string: str | None = None
    avoid_addresses: tuple[int, ...] = ()
    avoid_strings: tuple[str, ...] = ()
    length: int | None = None
    """Exact length of the argv string, or of the first stdin line."""
    max_length: int = 64
    """Longest argv string considered when no exact length is given."""
    prefix: bytes = b""
    suffix: bytes = b""
    """The argv string, or the first stdin line, ends with these bytes."""
    charset: Charset | None = None
    solutions: int = 1
    budget: Budget = field(default_factory=Budget)
    emit_smt2: bool = False
    """Include the goal path's constraints as SMT-LIB in the result."""
    native: SandboxOptions | None = None
    """Also run each solution natively in this sandbox (never done unless requested)."""
    strategy: Strategy = field(default_factory=lambda: Strategy.AUTO)
    seed: bytes | None = None
    """The first input concolic search follows (default: any input the constraints allow)."""
    max_concolic_runs: int = 2000


class Strategy(StrEnum):
    AUTO = "auto"
    """Symbolic search, then concolic search if that ends without an answer."""
    SYMBOLIC = "symbolic"
    CONCOLIC = "concolic"


class SolveStatus(StrEnum):
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    INCOMPLETE = "analysis incomplete"
    UNSUPPORTED = "unsupported semantics"
    BUDGET_EXHAUSTED = "budget exhausted"


@dataclass(frozen=True, slots=True)
class InputDescription:
    kind: InputKind
    index: int | None
    capacity: int
    """Symbolic bytes available to the solver."""
    discovered: bool
    evidence: tuple[str, ...]
    name: str = ""
    """The path, for a file the program reads."""

    def label(self) -> str:
        if self.kind is InputKind.ARGV:
            return f"argv[{self.index}]"
        return self.name if self.kind is InputKind.FILE else "stdin"

    @property
    def max_bytes(self) -> int:
        """Longest input considered (an argv string also needs its terminating NUL)."""
        return self.capacity - 1 if self.kind is InputKind.ARGV else self.capacity


@dataclass(frozen=True, slots=True)
class NativeVerification:
    passed: bool | None
    """None when the goal prints nothing recognisable to look for."""
    detail: str


@dataclass(frozen=True, slots=True)
class Solution:
    argv: bytes | None
    stdin: bytes | None
    verified: bool
    """Concrete RevIR execution with these inputs reaches the goal before any avoid address."""
    verification: str
    native: NativeVerification | None = None
    """The sandboxed native run, when one was requested."""
    traced: bool = False
    """The answer only works while a debugger traces the program."""
    clock: int | None = None
    """The second the clock has to read, when the program asked it."""
    files: tuple[tuple[str, bytes], ...] = ()
    """What each file the program reads has to contain."""


@dataclass(frozen=True, slots=True)
class ConstraintRecord:
    kind: ConstraintKind
    text: str
    function: str | None
    address: int | None


@dataclass(frozen=True, slots=True)
class SolveStatistics:
    functions_lifted: int
    relevant_blocks: int
    symbolic_operations: int
    symbolic_branches: int
    states: int
    solver_calls: int
    seconds: float
    sliced_operations: int = 0
    """Operations skipped because they cannot influence reaching the goal."""
    solver_seconds: float = 0.0
    peak_states: int = 0
    path_constraints: int = 0
    """Constraints on the path to the first solution."""


@dataclass(frozen=True, slots=True)
class SolveResult:
    target: str
    entry: str
    inputs: tuple[InputDescription, ...]
    goal: GoalCandidate
    avoid: tuple[GoalCandidate, ...]
    status: SolveStatus
    backend: str
    solutions: tuple[Solution, ...]
    constraints: tuple[ConstraintRecord, ...]
    statistics: SolveStatistics
    notes: tuple[str, ...]
    smt2: str | None = None
    """The goal path's constraints as SMT-LIB, when requested and a path was found."""


def solve_module(
    module: Module,
    request: SolveRequest,
    backend: SolverBackend | None = None,
    progress: Progress | None = None,
) -> SolveResult:
    started = time.monotonic()
    backend = backend or Z3Backend()
    main = find_main(module)
    reachable = reachable_functions(module, main)
    goal, avoid = _select_goals(module, reachable, request)
    inputs = _select_inputs(module, main, request)
    reachability = GoalReachability(module, frozenset({goal.address}))
    program_slice = backward_slice(
        module,
        frozenset({goal.address, *(candidate.address for candidate in avoid)}),
        main.entry,
    )

    def executor() -> Executor:
        return Executor(
            module,
            backend,
            _executor_goal(goal, avoid),
            SymbolicLibc(calling_convention(module.target)),
            request.budget,
            reachability,
            program_slice,
            progress,
        )

    search = executor()
    _, initialization = started_image(module)
    state, symbols = _initial_state(search, module, main, inputs, request)
    notes: list[str] = []
    solutions: list[Solution] = []
    exploration: Exploration | None = None
    status = SolveStatus.INCOMPLETE
    if request.strategy is not Strategy.CONCOLIC:
        exploration = search.explore(state, max_reached=max(1, request.solutions))
        solutions, notes = _solutions(
            search, module, main, request, inputs, symbols, exploration, goal, avoid
        )
        status = _status(exploration, solutions, initialization)
        notes += _incomplete_notes(exploration)
    if request.strategy is Strategy.CONCOLIC or (
        request.strategy is Strategy.AUTO and status in _CONCOLIC_FALLBACK
    ):
        concolic = executor()
        start_state, _ = _initial_state(concolic, module, main, inputs, request)
        result = concolic_search(
            concolic,
            lambda: _initial_state(concolic, module, main, inputs, request)[0],
            symbols.all(),
            _seed(concolic, start_state, symbols, request),
            reachability,
            request.max_concolic_runs,
            request.budget.max_seconds,
        )
        notes.append(
            f"concolic search: {result.runs} runs, {result.flips} flipped choices"
            + ("" if result.exploration.reached else ", no run reached the goal")
        )
        if result.exploration.reached or request.strategy is Strategy.CONCOLIC:
            search, exploration = concolic, result.exploration
            solutions, concolic_notes = _solutions(
                search, module, main, request, inputs, symbols, exploration, goal, avoid
            )
            notes += concolic_notes
            status = _concolic_status(result, solutions, initialization)
    reached = exploration.reached[0].state if exploration and exploration.reached else None
    smt2 = (
        search.session.smt2(reached.conditions())
        if request.emit_smt2 and reached is not None
        else None
    )
    statistics = search.statistics
    return SolveResult(
        target=f"{module.target.architecture} Linux ELF",
        entry=main.name,
        inputs=tuple(inputs),
        goal=goal,
        avoid=tuple(avoid),
        status=status,
        backend=backend.name,
        solutions=tuple(solutions),
        constraints=_constraints(reached),
        statistics=SolveStatistics(
            functions_lifted=len(module.functions),
            relevant_blocks=len(statistics.blocks),
            symbolic_operations=statistics.steps,
            symbolic_branches=statistics.forks,
            states=statistics.states,
            solver_calls=statistics.solver_calls,
            seconds=time.monotonic() - started,
            sliced_operations=statistics.sliced,
            solver_seconds=statistics.solver_seconds,
            peak_states=statistics.peak_states,
            path_constraints=0 if reached is None else len(reached.constraints),
        ),
        notes=tuple(
            dict.fromkeys(
                notes
                + _unsat_notes(status, inputs)
                + _flag_format_note(module, request, solutions)
                + _initializer_note(initialization)
            )
        ),
        smt2=smt2,
    )


_CONCOLIC_FALLBACK = frozenset(
    {
        SolveStatus.BUDGET_EXHAUSTED,
        SolveStatus.TIMEOUT,
        SolveStatus.INCOMPLETE,
        SolveStatus.UNSUPPORTED,
        SolveStatus.UNKNOWN,
    }
)


def _concolic_status(
    result: ConcolicResult, solutions: list[Solution], initialization: Initialization
) -> SolveStatus:
    if solutions:
        return SolveStatus.SAT
    exploration = result.exploration
    if exploration.reached:
        return SolveStatus.UNKNOWN
    if not result.exhausted:
        return SolveStatus.BUDGET_EXHAUSTED
    # Every choice of every run was flipped: all paths were followed, unless something
    # was approximated or cut short on the way.
    if exploration.statistics.hiding_approximations or exploration.incomplete:
        return SolveStatus.INCOMPLETE
    return SolveStatus.UNSAT if initialization.complete else SolveStatus.INCOMPLETE


def _seed(
    executor: Executor, state: State, symbols: _Symbols, request: SolveRequest
) -> dict[str, int]:
    """The first input concolic search follows."""
    if request.seed is not None:
        assignment: dict[str, int] = {}
        for content in symbols.argv.values():
            data = request.seed[: len(content) - 1]
            for position, symbol in enumerate(content):
                assignment[symbol.name] = data[position] if position < len(data) else 0
        for position, symbol in enumerate(symbols.stdin):
            assignment[symbol.name] = (
                request.seed[position] if position < len(request.seed) else 0x0A
            )
        return assignment
    preferred = executor.solve_with(state, symbols.all(), _printable_preference(symbols))
    if preferred is not None:
        return preferred
    return executor.solve(state, symbols.all()) or {}


def _shortest_line(
    executor: Executor, state: State, stdin: tuple[Expr, ...], extra: list[Expr]
) -> Expr | None:
    """A bound ending stdin's first line as early as this path allows, if it can end at all."""
    newline = sx.const(NEWLINE, 8)

    def ends_by(position: int) -> Expr:
        return sx.bool_or(*(sx.equal(symbol, newline) for symbol in stdin[: position + 1]))

    if not stdin or executor.solve_with(state, [], [*extra, ends_by(len(stdin) - 1)]) is None:
        return None
    low, high = 0, len(stdin) - 1
    while low < high:
        middle = (low + high) // 2
        if executor.solve_with(state, [], [*extra, ends_by(middle)]) is None:
            low = middle + 1
        else:
            high = middle
    return ends_by(low)


def reach(module: Module, request: SolveRequest, address: int) -> State | None:
    """Explore from main, with the request's inputs, until a path reaches `address`.

    Returns that path's state at the instruction, or None if no path reaches it.
    """
    main = find_main(module)
    inputs = _select_inputs(module, main, request)
    executor = Executor(
        module,
        Z3Backend(),
        Goal(addresses=frozenset({address})),
        SymbolicLibc(calling_convention(module.target)),
        request.budget,
        GoalReachability(module, frozenset({address})),
    )
    state, _ = _initial_state(executor, module, main, inputs, request)
    exploration = executor.explore(state)
    return exploration.reached[0].state if exploration.reached else None


# -- goals ---------------------------------------------------------------------------------


def _select_goals(
    module: Module, reachable: list[Function], request: SolveRequest
) -> tuple[GoalCandidate, list[GoalCandidate]]:
    references = string_references(module, reachable)
    ranked = rank_goals(references, printing_functions(module))
    if not any(candidate.outcome is Outcome.SUCCESS for candidate in ranked):
        found = sibling_successes(module, reachable, ranked, references)
        if not found:
            found = shaped_successes(module, reachable, ranked)
        ranked = sorted(
            [*ranked, *found],
            key=lambda candidate: (-candidate.confidence, candidate.address),
        )
    goal: GoalCandidate
    if request.goal_address is not None:
        address = executable_address(module, request.goal_address)
        evidence = ("given",) if address == request.goal_address else ("given", "first instruction")
        goal = GoalCandidate(address, Outcome.SUCCESS, "", "", 1.0, evidence)
    elif request.goal_string is not None:
        goal = _by_string(module, reachable, request.goal_string, Outcome.SUCCESS)
    else:
        successes = [candidate for candidate in ranked if candidate.outcome is Outcome.SUCCESS]
        if not successes:
            raise PpyRevError(
                "no likely success output found; pass --goal-address or --goal-string"
                + describe_messages(printed_messages(module, reachable))
            )
        goal = successes[0]
    avoid = [
        GoalCandidate(executable_address(module, address), Outcome.FAILURE, "", "", 1.0, ("given",))
        for address in request.avoid_addresses
    ]
    avoid.extend(
        _by_string(module, reachable, text, Outcome.FAILURE) for text in request.avoid_strings
    )
    if request.goal_address is None and request.goal_string is None and not avoid:
        # Only a message the program hands to something else is a failure branch. An
        # address that merely computes a pointer into the data is not: a table with no
        # terminator reads as the literal after it, and avoiding the instruction that
        # indexes that table would cut the loop the answer runs through.
        avoid = [
            candidate
            for candidate in ranked
            if candidate.outcome is Outcome.FAILURE and candidate.call is not None
        ]
    return goal, [candidate for candidate in avoid if candidate.address != goal.address]


def _by_string(
    module: Module, reachable: list[Function], text: str, outcome: Outcome
) -> GoalCandidate:
    needle = text.encode("latin-1")
    references = string_references(module, reachable)
    exact = [reference for reference in references if reference.text.rstrip(b"\n") == needle]
    matches = exact or [reference for reference in references if needle in reference.text]
    if not matches:
        raise PpyRevError(f"no code references a string containing {text!r}")
    reference = matches[0]
    return GoalCandidate(
        reference.instruction,
        outcome,
        reference.text.decode("latin-1"),
        reference.function,
        1.0,
        (f"string {text!r} requested",),
    )


# -- inputs --------------------------------------------------------------------------------


def _select_inputs(module: Module, main: Function, request: SolveRequest) -> list[InputDescription]:
    if request.argv is not None or request.stdin is not None:
        chosen: list[InputDescription] = []
        if request.argv is not None:
            chosen.append(
                InputDescription(InputKind.ARGV, request.argv, _argv_capacity(request), False, ())
            )
        if request.stdin is not None:
            chosen.append(InputDescription(InputKind.STDIN, None, request.stdin, False, ()))
        return chosen
    discovered = discover_inputs(module, main)
    if not discovered:
        raise PpyRevError("no input source found; pass --argv INDEX or --stdin LENGTH")
    return [_describe(candidate, request) for candidate in discovered]


def _argv_capacity(request: SolveRequest) -> int:
    """Symbolic bytes for an argv string: the longest input considered, plus its NUL."""
    hinted = len(request.prefix) + len(request.suffix)
    return max(request.max_length, request.length or 0, hinted) + 1


def _describe(candidate: InputCandidate, request: SolveRequest) -> InputDescription:
    if candidate.kind is InputKind.ARGV:
        return InputDescription(
            InputKind.ARGV, candidate.index, _argv_capacity(request), True, candidate.evidence
        )
    if candidate.kind is InputKind.FILE:
        return InputDescription(
            InputKind.FILE,
            None,
            DEFAULT_FILE_LENGTH,
            True,
            candidate.evidence,
            candidate.name,
        )
    return InputDescription(InputKind.STDIN, None, DEFAULT_STDIN_LENGTH, True, candidate.evidence)


@dataclass(frozen=True, slots=True)
class _Symbols:
    argv: dict[int, tuple[Expr, ...]]
    stdin: tuple[Expr, ...]
    files: dict[str, tuple[Expr, ...]] = field(default_factory=dict[str, tuple[Expr, ...]])

    def all(self) -> list[Expr]:
        return [
            *(symbol for symbols in self.argv.values() for symbol in symbols),
            *self.stdin,
            *(symbol for symbols in self.files.values() for symbol in symbols),
        ]


def started_image(module: Module) -> tuple[ConcreteMemory, Initialization]:
    """The image main really starts from: the program plus whatever its constructors wrote."""
    memory = program_memory(module)
    return memory, run_initializers(module, memory)


def _initial_state(
    executor: Executor,
    module: Module,
    main: Function,
    inputs: list[InputDescription],
    request: SolveRequest,
) -> tuple[State, _Symbols]:
    argv_inputs = {
        item.index: item for item in inputs if item.kind is InputKind.ARGV and item.index
    }
    count = max([0, *argv_inputs]) + 1
    arguments = [f"./{module.name}".encode()] + [b"" for _ in range(1, count)]
    image, started = started_image(module)
    entry = enter_main(
        module,
        image,
        arguments,
        {index: item.capacity for index, item in argv_inputs.items()},
    )
    memory = SymbolicMemory(image)
    symbols = _Symbols({}, (), {})
    stdin_length = next((item.capacity for item in inputs if item.kind is InputKind.STDIN), 0)
    state = State(
        id=executor.new_state_id(),
        frames=[],
        memory=memory,
        io=SymbolicIO(
            heap_next=started.heap_next,
            stdin=stdin_symbols(stdin_length),
            contents={
                item.name: file_symbols(item.name, item.capacity)
                for item in inputs
                if item.kind is InputKind.FILE
            },
        ),
    )
    symbols.files.update(state.io.contents)
    for index, item in sorted(argv_inputs.items()):
        content = argv_symbols(index, item.capacity)
        symbols.argv[index] = content
        for offset, symbol in enumerate(content):
            memory.write_byte(entry.argv_strings[index] + offset, symbol)
        for condition in argv_constraints(
            content, request.length, request.prefix, request.suffix, request.charset
        ):
            executor.add_constraint(state, condition, ConstraintKind.INPUT, None, f"argv[{index}]")
    if stdin_length:
        symbols = _Symbols(symbols.argv, state.io.stdin, symbols.files)
        line_length = None if argv_inputs else request.length
        prefix = b"" if argv_inputs else request.prefix
        suffix = b"" if argv_inputs else request.suffix
        for condition in stdin_constraints(
            state.io.stdin, line_length, prefix, suffix, request.charset
        ):
            executor.add_constraint(state, condition, ConstraintKind.INPUT, None, "stdin")
    values = {
        item.value.id: sx.const(entry.registers.get(item.register, 0), item.value.width)
        for item in main.inputs
    }
    state.frames.append(
        Frame(
            function=main,
            block=0,
            position=0,
            values=values,
            expected_return=sx.const(entry.return_address, module.target.pointer_width),
            resume=None,
        )
    )
    return state, symbols


# -- solutions -----------------------------------------------------------------------------


def _solutions(
    executor: Executor,
    module: Module,
    main: Function,
    request: SolveRequest,
    inputs: list[InputDescription],
    symbols: _Symbols,
    exploration: Exploration,
    goal: GoalCandidate,
    avoid: list[GoalCandidate],
) -> tuple[list[Solution], list[str]]:
    solutions: list[Solution] = []
    notes: list[str] = []
    seen: set[tuple[bytes | None, bytes | None]] = set()
    watches = (_watch("goal", goal), *(_watch("avoid", candidate) for candidate in avoid))
    all_symbols = symbols.all()
    has_stdin = any(item.kind is InputKind.STDIN for item in inputs)

    def shortest(state: State, extra: list[Expr]) -> list[Expr]:
        """Bounds making each argv string, and the first line of stdin, as short as possible."""
        bounds: list[Expr] = []
        for _, content in sorted(symbols.argv.items()):
            low, high = 0, len(content) - 1
            while low < high:
                middle = (low + high) // 2
                ends = sx.equal(content[middle], sx.const(0, 8))
                if executor.solve_with(state, [], [*extra, *bounds, ends]) is None:
                    low = middle + 1
                else:
                    high = middle
            bounds.append(sx.equal(content[low], sx.const(0, 8)))
        line = _shortest_line(executor, state, symbols.stdin, [*extra, *bounds])
        return bounds if line is None else [*bounds, line]

    def extract(state: State, extra: list[Expr]) -> bool:
        """Add solutions from `state` under `extra`; report whether any model existed."""
        if executor.solve_with(state, [], extra) is None:
            return False
        blocking: list[Expr] = []
        bounds = shortest(state, extra)
        found = False
        while len(solutions) < request.solutions:
            traced_symbol = state.io.traced
            opened = dict(sorted(state.io.contents.items()))
            wanted = [*all_symbols, *(symbol for content in opened.values() for symbol in content)]
            for chosen in (traced_symbol, state.io.clock):
                if chosen is not None:
                    wanted.append(chosen)
            model = executor.solve_with(state, wanted, [*blocking, *extra, *bounds])
            if model is None and bounds:
                bounds = []  # other solutions may need longer strings
                continue
            if model is None:
                break
            found = True
            argv = next(
                (argv_solution(content, model) for _, content in sorted(symbols.argv.items())), None
            )
            stdin = (
                stdin_solution(symbols.stdin, model, state.io.stdin_reads) if has_stdin else None
            )
            traced = traced_symbol is not None and model.get(TRACED_SYMBOL, 0) != 0
            clock = model.get(CLOCK_SYMBOL) if state.io.clock is not None else None
            files = tuple(
                (name, _file_content(name, content, model, state.io))
                for name, content in opened.items()
            )
            if not argv and not stdin and not any(content for _, content in files):
                notes.append(
                    "the goal is reached without reading the input: this answer says "
                    "nothing about what the program wants"
                )
            blocking.append(_block(symbols, argv, stdin))
            if (argv, stdin) not in seen:
                seen.add((argv, stdin))
                solutions.append(
                    _verify(
                        module,
                        main,
                        request,
                        goal,
                        symbols,
                        argv,
                        stdin,
                        watches,
                        traced,
                        files,
                        clock,
                    )
                )
        return found

    # Prefer printable input, looking at a few more goal paths for it, but never require it.
    preference = _printable_preference(symbols) if request.charset is None else []
    unpreferred: list[State] = []
    index = 0
    while len(solutions) < request.solutions:
        if index >= len(exploration.reached):
            if not preference or index >= PREFERENCE_PATHS or executor.exhausted:
                break
            exploration = executor.resume(index + 1)
            if index >= len(exploration.reached):
                break
        state = exploration.reached[index].state
        index += 1
        notes.extend(note for note in state.io.approximations if note not in notes)
        if not extract(state, preference) and preference:
            unpreferred.append(state)
    for state in unpreferred:
        if len(solutions) >= request.solutions:
            break
        extract(state, [])
    return solutions, notes


def _executor_goal(goal: GoalCandidate, avoid: list[GoalCandidate]) -> Goal:
    def condition(candidate: GoalCandidate) -> CallCondition | None:
        if candidate.register is None or candidate.string_address is None:
            return None
        return CallCondition(candidate.address, candidate.register, candidate.string_address)

    goal_call = condition(goal)
    avoid_calls = tuple(call for call in map(condition, avoid) if call is not None)
    avoid_addresses = frozenset(
        candidate.address for candidate in avoid if condition(candidate) is None
    )
    if goal_call is None:
        return Goal(
            addresses=frozenset({goal.address}),
            avoid=avoid_addresses - {goal.address},
            avoid_calls=avoid_calls,
        )
    return Goal(calls=(goal_call,), avoid=avoid_addresses, avoid_calls=avoid_calls)


def _watch(name: str, candidate: GoalCandidate) -> Watch:
    if candidate.register is not None and candidate.string_address is not None:
        return Watch(name, candidate.address, candidate.register, candidate.string_address)
    return Watch(name, candidate.address)


def _printable_preference(symbols: _Symbols) -> list[Expr]:
    preferred: list[Expr] = []
    for content in symbols.argv.values():
        preferred.extend(
            sx.bool_or(sx.equal(byte, sx.const(0, 8)), in_charset(byte, Charset.PRINTABLE))
            for byte in content
        )
    preferred.extend(
        sx.bool_or(sx.equal(byte, sx.const(0x0A, 8)), in_charset(byte, Charset.PRINTABLE))
        for byte in symbols.stdin
    )
    return preferred


def _block(symbols: _Symbols, argv: bytes | None, stdin: bytes | None) -> Expr:
    """A clause excluding exactly this solution."""
    differences: list[Expr] = []
    if argv is not None:
        content = next(iter(symbols.argv.values()))
        for position, symbol in enumerate(content):
            value = argv[position] if position < len(argv) else 0
            differences.append(sx.bool_not(sx.equal(symbol, sx.const(value, 8))))
            if position >= len(argv):
                break
    if stdin is not None:
        for position, value in enumerate(stdin):
            differences.append(sx.bool_not(sx.equal(symbols.stdin[position], sx.const(value, 8))))
    return sx.bool_or(*differences) if differences else sx.FALSE


def _file_content(
    name: str, content: tuple[Expr, ...], model: dict[str, int], io: SymbolicIO
) -> bytes:
    """What a file has to contain: as far as the program read it.

    A file is not NUL-terminated, so cutting at the first zero byte would drop whatever
    the program went on to read — the newline ending a line, say. A file read a line at a
    time ends with that line, since nothing past it was ever looked at.
    """
    raw = bytes(model.get(symbol.name, 0) for symbol in content)
    terminator = raw.find(b"\0")
    end = max(len(raw) if terminator < 0 else terminator, io.read_to.get(name, 0))
    newline = raw.find(b"\n")
    if name in io.line_read and 0 <= newline < end:
        return raw[: newline + 1]
    return raw[:end]


def _verify(
    module: Module,
    main: Function,
    request: SolveRequest,
    goal: GoalCandidate,
    symbols: _Symbols,
    argv: bytes | None,
    stdin: bytes | None,
    watches: tuple[Watch, ...],
    traced: bool = False,
    files: tuple[tuple[str, bytes], ...] = (),
    clock: int | None = None,
) -> Solution:
    reserve = {index: len(content) for index, content in symbols.argv.items()}
    arguments = _arguments(module, reserve, argv)
    verified, verification = _run_verification(
        module, main, arguments, stdin, watches, reserve, traced, dict(files), clock
    )
    if request.native is None:
        native = None
    elif traced:
        native = NativeVerification(None, "not run: this answer needs a debugger attached")
    elif clock is not None:
        native = NativeVerification(
            None, f"not run: this answer needs the clock to read {clock} seconds"
        )
    elif files:
        named = ", ".join(name for name, _ in files)
        native = NativeVerification(None, f"not run: the answer is the contents of {named}")
    else:
        native = _run_native(request, arguments, stdin, goal)
    return Solution(argv, stdin, verified, verification, native, traced, clock, files)


def _arguments(module: Module, reserve: dict[int, int], argv: bytes | None) -> list[bytes]:
    count = max([0, *reserve]) + 1
    arguments = [f"./{module.name}".encode()] + [b"" for _ in range(1, count)]
    for index in reserve:
        arguments[index] = argv or b""
    return arguments


def _run_verification(
    module: Module,
    main: Function,
    arguments: list[bytes],
    stdin: bytes | None,
    watches: tuple[Watch, ...],
    reserve: dict[int, int],
    traced: bool = False,
    files: dict[str, bytes] | None = None,
    clock: int | None = None,
) -> tuple[bool, str]:
    run = run_program(
        module,
        main,
        arguments,
        stdin or b"",
        watches,
        reserve=reserve,
        traced=traced,
        files=files,
        clock=clock,
    )
    verified = run.first_watch is not None and run.first_watch.name == "goal"
    return verified, "reaches the goal" if verified else run.outcome


def verify_on(module: Module, result: SolveResult) -> SolveResult:
    """`result` with every solution re-checked by concrete RevIR execution of `module`.

    For solutions found on a transformed program (bytecode lifted out of its interpreter),
    this checks them against the program as lifted from the binary.
    """
    main = find_main(module)
    watches = (_watch("goal", result.goal), *(_watch("avoid", item) for item in result.avoid))
    reserve = {
        item.index: item.capacity
        for item in result.inputs
        if item.kind is InputKind.ARGV and item.index is not None
    }
    solutions: list[Solution] = []
    for solution in result.solutions:
        arguments = _arguments(module, reserve, solution.argv)
        verified, verification = _run_verification(
            module, main, arguments, solution.stdin, watches, reserve
        )
        solutions.append(replace(solution, verified=verified, verification=verification))
    return replace(result, solutions=tuple(solutions))


def _run_native(
    request: SolveRequest, arguments: list[bytes], stdin: bytes | None, goal: GoalCandidate
) -> NativeVerification:
    if request.native is None:
        raise AssertionError("native verification was not requested")
    run = run_sandboxed(request.binary, arguments[1:], stdin or b"", request.native)
    if run.exit_status is None:
        limit = request.native.timeout_seconds
        return NativeVerification(False, f"stopped after {limit:g}s without finishing")
    status = f"exit status {run.exit_status}"
    if not goal.text:
        return NativeVerification(None, f"{status}; no goal output to look for")
    fragments = _printed_fragments(goal.text)
    if not fragments:
        return NativeVerification(None, f"{status}; the goal output is only a format")
    position = 0
    for fragment in fragments:
        found = run.stdout.find(fragment, position)
        if found < 0:
            return NativeVerification(False, f"{status}, does not print {json.dumps(goal.text)}")
        position = found + len(fragment)
    return NativeVerification(True, f"{status}, prints {json.dumps(goal.text)}")


_CONVERSION = re.compile(r"%[-+ #0-9.*hlLqjzt]*[diouxXeEfgGaAcsp%]")


def _printed_fragments(text: str) -> list[bytes]:
    """The parts of a message that reach the output whatever its arguments are."""
    return [
        part.encode("latin-1")
        for piece in _CONVERSION.split(text)
        if (part := piece.strip("\n")) and len(part) >= 4
    ]


def _status(
    exploration: Exploration, solutions: list[Solution], initialization: Initialization
) -> SolveStatus:
    if solutions:
        return SolveStatus.SAT
    if exploration.reached:
        # Goal states are checked satisfiable when reached; failing to extract a model
        # afterwards means the solver gave up, which says nothing about satisfiability.
        return SolveStatus.UNKNOWN
    if exploration.timed_out:
        return SolveStatus.TIMEOUT
    if exploration.statistics.hiding_approximations:
        return SolveStatus.INCOMPLETE
    if exploration.budget_exhausted is not None:
        return SolveStatus.BUDGET_EXHAUSTED
    reasons = {stop.reason for stop in exploration.incomplete}
    if StopReason.SOLVER_UNKNOWN in reasons:
        return SolveStatus.UNKNOWN
    if StopReason.UNSUPPORTED in reasons:
        return SolveStatus.UNSUPPORTED
    if reasons & INCOMPLETE_REASONS:
        return SolveStatus.INCOMPLETE
    # `unsat` claims every path was explored; a constructor that would not run means
    # main started from an image the real program never has.
    return SolveStatus.UNSAT if initialization.complete else SolveStatus.INCOMPLETE


def _constraints(state: State | None) -> tuple[ConstraintRecord, ...]:
    if state is None:
        return ()
    return tuple(
        ConstraintRecord(
            constraint.kind,
            sx.render(constraint.condition, 240),
            constraint.function,
            None if constraint.origin is None else constraint.origin.address,
        )
        for constraint in state.constraints
        if constraint.kind is not ConstraintKind.INPUT
    )


def _initializer_note(initialization: Initialization) -> list[str]:
    """Say which constructors could not be run, since main then starts from less."""
    return [f"code runs before main: {note} (not modeled)" for note in initialization.notes()]


def _flag_format_note(
    module: Module, request: SolveRequest, solutions: list[Solution]
) -> list[str]:
    """Point at `--flag-format` when the program mentions a flag the answer does not match."""
    if not solutions or request.prefix or request.suffix:
        return []
    prefixes = flag_prefixes(module)
    if not prefixes:
        return []
    answers = [solution.argv or solution.stdin or b"" for solution in solutions]
    if any(
        answer.startswith(prefix.encode("latin-1")) for answer in answers for prefix in prefixes
    ):
        return []
    shape = f"{prefixes[0]}*}}"
    return [f"the program mentions {prefixes[0]!r}: try --flag-format {shape!r} for the flag"]


def _incomplete_notes(exploration: Exploration) -> list[str]:
    notes: list[str] = []
    if exploration.budget_exhausted is not None:
        notes.append(f"exploration stopped after {exploration.budget_exhausted}")
    notes.extend(
        f"approximated: {note}" for note in sorted(exploration.statistics.hiding_approximations)
    )
    for stop in exploration.incomplete[:10]:
        notes.append(_describe_stop(stop))
    return notes


def _unsat_notes(status: SolveStatus, inputs: list[InputDescription]) -> list[str]:
    if status is not SolveStatus.UNSAT:
        return []
    bounds = ", ".join(f"{item.label()} up to {item.max_bytes} bytes" for item in inputs)
    return [f"every path was explored and none reaches the goal with {bounds}"]


def _describe_stop(stop: Stopped) -> str:
    where = f" in {stop.function}" if stop.function else ""
    address = f" at {stop.address:#x}" if stop.address is not None else ""
    return f"{stop.reason}{where}{address}: {stop.detail}"

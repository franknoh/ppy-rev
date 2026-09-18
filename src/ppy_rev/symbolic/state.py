"""Symbolic machine states."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ppy_rev.ir.model import Call, Function, Origin
from ppy_rev.summaries.glibc_random import UNSEEDED, RandomState
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.memory import SymbolicMemory


class ConstraintKind(StrEnum):
    BRANCH = "branch"
    DIVISOR = "divisor"
    POINTER = "pointer"
    RETURN_ADDRESS = "return-address"
    INPUT = "input"
    LIBRARY = "library"
    ENVIRONMENT = "environment"
    GOAL = "goal"


@dataclass(frozen=True, slots=True)
class Constraint:
    """A path condition together with where and why it was introduced."""

    condition: Expr
    kind: ConstraintKind
    function: str | None = None
    origin: Origin | None = None
    note: str = ""


@dataclass(frozen=True, slots=True)
class OpenFile:
    """A file the program opened, whose contents are an input like any other."""

    name: str
    content: tuple[Expr, ...]


@dataclass(slots=True)
class SymbolicIO:
    """Process I/O visible to library models."""

    stdin: tuple[Expr, ...] = ()
    stdin_position: int = 0
    stdin_reads: list[tuple[int, int, bool]] = field(default_factory=list[tuple[int, int, bool]])
    """(start, end, line-based) windows of stdin handed to the program, in order."""
    stdout: list[Expr] = field(default_factory=list[Expr])
    """Bytes written to standard output, in order."""
    heap_next: int = 0
    random: RandomState = UNSEEDED
    """glibc's rand state, which only a concrete srand seed changes."""
    approximations: list[str] = field(default_factory=list[str])
    """Places where a library model over-approximated a result."""
    contents: dict[str, tuple[Expr, ...]] = field(default_factory=dict[str, tuple[Expr, ...]])
    """What each file the program may open contains: an input, like stdin."""
    files: dict[int, OpenFile] = field(default_factory=dict[int, OpenFile])
    """Streams `fopen` returned, by the handle the program holds."""
    positions: dict[int, int] = field(default_factory=dict[int, int])
    """How far each open file has been read."""
    traced: Expr | None = None
    """`ptrace(PTRACE_TRACEME)`'s result: 0, or -1 when a debugger already traces us.

    One value per run, chosen by the solver rather than assumed, because challenges exist
    that only reveal their answer under a debugger.
    """

    def copy(self) -> SymbolicIO:
        return SymbolicIO(
            stdin=self.stdin,
            stdin_position=self.stdin_position,
            stdin_reads=list(self.stdin_reads),
            stdout=list(self.stdout),
            heap_next=self.heap_next,
            random=self.random,
            approximations=list(self.approximations),
            contents=dict(self.contents),
            files=dict(self.files),
            positions=dict(self.positions),
            traced=self.traced,
        )


@dataclass(slots=True)
class Frame:
    function: Function
    block: int
    position: int
    values: dict[int, Expr]
    expected_return: Expr | None
    """The return address the caller pushed; None for the outermost frame."""
    resume: Call | None
    """The caller's call operation whose results this frame provides."""
    tail: bool = False

    def copy(self) -> Frame:
        return Frame(
            function=self.function,
            block=self.block,
            position=self.position,
            values=dict(self.values),
            expected_return=self.expected_return,
            resume=self.resume,
            tail=self.tail,
        )


@dataclass(slots=True)
class State:
    id: int
    frames: list[Frame]
    memory: SymbolicMemory
    constraints: list[Constraint] = field(default_factory=list[Constraint])
    steps: int = 0
    branch_counts: dict[tuple[int, int], int] = field(default_factory=dict[tuple[int, int], int])
    decisions: int = 0
    """Symbolic branches on this path where more than one direction was feasible."""
    outputs: dict[str, Expr] = field(default_factory=dict[str, Expr])
    """Register values returned by the outermost frame, once it has returned."""
    io: SymbolicIO = field(default_factory=lambda: SymbolicIO())

    def fork(self, identifier: int) -> State:
        return State(
            id=identifier,
            frames=[frame.copy() for frame in self.frames],
            memory=self.memory.fork(),
            constraints=list(self.constraints),
            steps=self.steps,
            branch_counts=dict(self.branch_counts),
            decisions=self.decisions,
            outputs=dict(self.outputs),
            io=self.io.copy(),
        )

    @property
    def frame(self) -> Frame:
        return self.frames[-1]

    def conditions(self) -> list[Expr]:
        return [constraint.condition for constraint in self.constraints]

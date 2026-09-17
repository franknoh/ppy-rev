"""Symbolic machine states."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ppy_rev.ir.model import Call, Function, Origin
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.memory import SymbolicMemory


class ConstraintKind(StrEnum):
    BRANCH = "branch"
    DIVISOR = "divisor"
    POINTER = "pointer"
    RETURN_ADDRESS = "return-address"
    INPUT = "input"
    LIBRARY = "library"
    GOAL = "goal"


@dataclass(frozen=True, slots=True)
class Constraint:
    """A path condition together with where and why it was introduced."""

    condition: Expr
    kind: ConstraintKind
    function: str | None = None
    origin: Origin | None = None
    note: str = ""


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
    outputs: dict[str, Expr] = field(default_factory=dict[str, Expr])
    """Register values returned by the outermost frame, once it has returned."""

    def fork(self, identifier: int) -> State:
        return State(
            id=identifier,
            frames=[frame.copy() for frame in self.frames],
            memory=self.memory.fork(),
            constraints=list(self.constraints),
            steps=self.steps,
            branch_counts=dict(self.branch_counts),
            outputs=dict(self.outputs),
        )

    @property
    def frame(self) -> Frame:
        return self.frames[-1]

    def conditions(self) -> list[Expr]:
        return [constraint.condition for constraint in self.constraints]

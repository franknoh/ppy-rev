"""The narrow interface symbolic execution needs from an SMT solver."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from ppy_rev.symbolic.expr import Expr


class Status(StrEnum):
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class CheckResult:
    status: Status
    model: Mapping[str, int]
    """Values of the requested symbols when satisfiable; empty otherwise."""
    reason: str | None = None


class SolverSession(Protocol):
    """An incremental solver: assertions persist across checks within push/pop scopes."""

    def add(self, constraint: Expr) -> None: ...

    def push(self) -> None: ...

    def pop(self) -> None: ...

    def check(
        self,
        assumptions: Sequence[Expr] = (),
        symbols: Sequence[Expr] = (),
        timeout_ms: int | None = None,
    ) -> CheckResult:
        """Check the current assertions plus `assumptions`; report `symbols` from the model."""
        ...

    def smt2(self, assumptions: Sequence[Expr] = ()) -> str: ...


class SolverBackend(Protocol):
    name: str

    def session(self) -> SolverSession: ...

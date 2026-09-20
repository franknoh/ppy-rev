"""What the loader runs before main: the constructors in `.init_array`.

A constructor that fills a table, or builds a global `std::string`, decides what main
sees. Starting at main with that memory still zeroed analyzes a different program, and
the answer that comes out is one the real binary rejects — the worst kind of wrong, since
it looks like a solution. So they are run here, concretely, on the image the analysis is
about to use, before anything symbolic begins.

A constructor whose behaviour depends on something not known yet — it reads the input,
looks for a debugger, or exits — is not run at all. Guessing what it would do is exactly
what this module exists to avoid; such a constructor is reported instead.
"""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.abi import calling_convention
from ppy_rev.analysis.program import deferred_initializers, initializer_functions
from ppy_rev.execution.interpreter import ExecutionError, Interpreter, Limits
from ppy_rev.execution.memory import ConcreteMemory
from ppy_rev.execution.process import enter_call
from ppy_rev.ir.model import Module
from ppy_rev.summaries.concrete import (
    ConcreteIO,
    ConcreteLibc,
    ProgramExitError,
    UnsupportedLibraryCallError,
)

INITIALIZER_LIMITS = Limits(max_steps=200_000, max_call_depth=64)
"""A constructor that does not finish quickly is not the input-independent setup we run."""


@dataclass(frozen=True, slots=True)
class Initialization:
    """What running the constructors did to the image main starts with."""

    ran: tuple[str, ...]
    """Constructors that ran to completion; their writes are in the memory."""
    stopped: tuple[tuple[str, str], ...]
    """Constructors that could not be run, and why — their writes may be missing."""

    @property
    def complete(self) -> bool:
        return not self.stopped

    def notes(self) -> list[str]:
        return [f"{name} runs before main and stopped: {why}" for name, why in self.stopped]


def run_initializers(module: Module, memory: ConcreteMemory) -> Initialization:
    """Run every constructor that can be run, writing into `memory`."""
    deferred = {item.address: item for item in deferred_initializers(module)}
    convention = calling_convention(module.target)
    ran: list[str] = []
    stopped: list[tuple[str, str]] = []
    for function in initializer_functions(module):
        waiting = deferred.get(function.entry)
        if waiting is not None:
            calls = ", ".join(waiting.library_calls)
            stopped.append((function.name, f"it calls {calls}, which needs the input"))
            continue
        libc = ConcreteLibc(convention, ConcreteIO())
        interpreter = Interpreter(module, memory, libc, INITIALIZER_LIMITS)
        frame = enter_call(module, memory, dict.fromkeys(convention.integer_parameters[:3], 0))
        try:
            interpreter.call(function, frame.registers, frame.return_address)
        except (ExecutionError, UnsupportedLibraryCallError, ProgramExitError) as error:
            stopped.append((function.name, str(error)))
            continue
        ran.append(function.name)
    return Initialization(tuple(ran), tuple(stopped))

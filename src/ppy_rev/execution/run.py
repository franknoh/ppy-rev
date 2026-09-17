"""Running a lifted program concretely from main with given arguments and input."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ppy_rev.abi import calling_convention
from ppy_rev.execution.interpreter import ExecutionError, Interpreter, Limits
from ppy_rev.execution.program import enter_main, program_memory
from ppy_rev.ir.model import Function, Module
from ppy_rev.summaries.concrete import (
    ConcreteIO,
    ConcreteLibc,
    ProgramExitError,
    UnsupportedLibraryCallError,
)


@dataclass(frozen=True, slots=True)
class Watch:
    """A point of interest: an instruction, optionally only with a register holding a value."""

    name: str
    address: int
    register: str | None = None
    value: int | None = None


class _Watched(Exception):  # noqa: N818 - internal control flow
    def __init__(self, watch: Watch) -> None:
        super().__init__(watch.name)
        self.watch = watch


@dataclass(frozen=True, slots=True)
class ProgramRun:
    first_watch: Watch | None
    """The first watch that triggered; execution stops there."""
    outcome: str
    stdout: bytes
    steps: int


def run_program(
    module: Module,
    main: Function,
    arguments: list[bytes],
    stdin: bytes = b"",
    watches: tuple[Watch, ...] = (),
    limits: Limits | None = None,
) -> ProgramRun:
    """Execute main until it returns, exits, fails, or triggers a watch."""
    memory = program_memory(module)
    entry = enter_main(module, memory, arguments)
    io = ConcreteIO(stdin=stdin)
    libc = ConcreteLibc(calling_convention(module.target), io)
    at_instruction = {watch.address: watch for watch in watches if watch.register is None}
    at_call = [watch for watch in watches if watch.register is not None]

    def observe(address: int) -> None:
        watch = at_instruction.get(address)
        if watch is not None:
            raise _Watched(watch)

    def observe_call(address: int, registers: Mapping[str, int]) -> None:
        for watch in at_call:
            if watch.address == address and registers.get(watch.register or "") == watch.value:
                raise _Watched(watch)

    interpreter = Interpreter(
        module,
        memory,
        libc,
        limits,
        observe if at_instruction else None,
        observe_call if at_call else None,
    )
    try:
        outputs = interpreter.call(main, entry.registers, entry.return_address)
    except _Watched as watched:
        return ProgramRun(watched.watch, watched.watch.name, bytes(io.stdout), interpreter.steps)
    except ProgramExitError as exited:
        return ProgramRun(None, exited.detail, bytes(io.stdout), interpreter.steps)
    except (ExecutionError, UnsupportedLibraryCallError) as error:
        return ProgramRun(None, f"stopped: {error}", bytes(io.stdout), interpreter.steps)
    status = outputs.get(calling_convention(module.target).integer_returns[0], 0) & 0xFF
    return ProgramRun(None, f"main returned {status}", bytes(io.stdout), interpreter.steps)

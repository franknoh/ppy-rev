"""Setting up symbolic states for a single function call."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ppy_rev.execution.process import enter_call, standard_memory
from ppy_rev.ir.model import Function, Module
from ppy_rev.solver.backend import SolverBackend
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.executor import Budget, Executor, Exploration, ExternalModels, Goal
from ppy_rev.symbolic.expr import Expr
from ppy_rev.symbolic.memory import SymbolicMemory
from ppy_rev.symbolic.state import Frame, State


@dataclass(frozen=True, slots=True)
class FunctionSolution:
    exploration: Exploration
    model: dict[str, int] | None
    """Values for the symbolic registers, when a goal state is satisfiable."""


def call_state(
    executor: Executor,
    module: Module,
    function: Function,
    symbolic: Mapping[str, Expr],
    concrete: Mapping[str, int] | None = None,
) -> State:
    """A state about to execute `function`, entered by a call from outside the module."""
    image = standard_memory(module)
    frame = enter_call(module, image, dict(concrete or {}))
    registers: dict[str, Expr] = {
        name: sx.const(value, module.register(name).width)
        for name, value in frame.registers.items()
        if any(register.name == name for register in module.registers)
    }
    registers.update(symbolic)
    values: dict[int, Expr] = {}
    for item in function.inputs:
        value = registers.get(item.register)
        values[item.value.id] = value if value is not None else sx.const(0, item.value.width)
    return State(
        id=executor.new_state_id(),
        frames=[
            Frame(
                function=function,
                block=0,
                position=0,
                values=values,
                expected_return=sx.const(frame.return_address, module.target.pointer_width),
                resume=None,
            )
        ],
        memory=SymbolicMemory(image),
    )


def solve_function(
    module: Module,
    function: Function,
    symbolic: Mapping[str, Expr],
    condition: Goal,
    backend: SolverBackend,
    externals: ExternalModels | None = None,
    budget: Budget | None = None,
) -> FunctionSolution:
    executor = Executor(module, backend, condition, externals, budget)
    exploration = executor.explore(call_state(executor, module, function, symbolic))
    if not exploration.reached:
        return FunctionSolution(exploration, None)
    model = executor.solve(exploration.reached[0].state, list(symbolic.values()))
    return FunctionSolution(exploration, model)

"""Which program points can still reach a goal: the basis of goal-directed exploration.

The analysis is interprocedural and conservative. A block can reach the goal if it contains
a goal instruction, calls a function that can reach the goal, or leads to such a block. A
state can reach the goal if some frame's current block can, and every frame above it can
still return. Indirect calls and jumps are assumed to reach anything, so pruning never
discards a state that could reach the goal.
"""

from __future__ import annotations

from collections.abc import Sequence

from ppy_rev.ir.cfg import control_flow
from ppy_rev.ir.model import (
    Call,
    DirectTarget,
    Function,
    IndirectJump,
    IndirectTarget,
    Module,
    Return,
    TailCall,
)


class GoalReachability:
    def __init__(self, module: Module, goals: frozenset[int]) -> None:
        self.module = module
        self.goals = goals
        self._functions = {function.entry: function for function in module.functions}
        self.reaches_goal: dict[int, list[bool]] = {}
        self.reaches_return: dict[int, list[bool]] = {}
        self._solve()

    def _solve(self) -> None:
        for function in self.module.functions:
            self.reaches_return[function.entry] = self._backward(
                function, [self._returns(block_id, function) for block_id in _ids(function)]
            )
            self.reaches_goal[function.entry] = [False] * len(function.blocks)
        changed = True
        while changed:
            changed = False
            for function in self.module.functions:
                seeds = [self._touches_goal(function, block_id) for block_id in _ids(function)]
                reached = self._backward(function, seeds)
                if reached != self.reaches_goal[function.entry]:
                    self.reaches_goal[function.entry] = reached
                    changed = True

    @staticmethod
    def _returns(block_id: int, function: Function) -> bool:
        terminator = function.blocks[block_id].terminator
        return isinstance(terminator, Return | TailCall | IndirectJump)

    def _touches_goal(self, function: Function, block_id: int) -> bool:
        block = function.blocks[block_id]
        if any(start.address in self.goals for start in block.instructions):
            return True
        calls = [operation for operation in block.operations if isinstance(operation, Call)]
        if isinstance(block.terminator, TailCall):
            calls.append(block.terminator.call)
        for call in calls:
            if call.origin.address in self.goals:
                return True
            match call.target:
                case IndirectTarget():
                    return True
                case DirectTarget(address=address) if address in self._functions:
                    if self.reaches_goal[address][0]:
                        return True
                case _:
                    pass
        return isinstance(block.terminator, IndirectJump) and not block.terminator.targets

    @staticmethod
    def _backward(function: Function, seeds: list[bool]) -> list[bool]:
        flow = control_flow(function)
        reached = list(seeds)
        work = [block_id for block_id, seeded in enumerate(seeds) if seeded]
        while work:
            block_id = work.pop()
            for predecessor in flow.predecessors[block_id]:
                if not reached[predecessor]:
                    reached[predecessor] = True
                    work.append(predecessor)
        return reached

    def can_reach(self, frames: Sequence[tuple[int, int]]) -> bool:
        """`frames` lists (function entry, current block id) from outermost to innermost."""
        for depth in range(len(frames) - 1, -1, -1):
            entry, block = frames[depth]
            goal = self.reaches_goal.get(entry)
            if goal is None or goal[block]:
                return True
            returns = self.reaches_return.get(entry)
            if returns is None or not returns[block]:
                return False
        return False


def _ids(function: Function) -> range:
    return range(len(function.blocks))

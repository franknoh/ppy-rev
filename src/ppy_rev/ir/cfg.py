"""Control-flow utilities over RevIR functions."""

from __future__ import annotations

from collections.abc import Container
from dataclasses import dataclass

from ppy_rev.ir.model import Function, successors


@dataclass(frozen=True, slots=True)
class ControlFlow:
    successors: tuple[tuple[int, ...], ...]
    predecessors: tuple[tuple[int, ...], ...]
    reverse_postorder: tuple[int, ...]
    immediate_dominators: tuple[int | None, ...]
    """None for the entry block and for blocks unreachable from it."""

    def reachable(self, block: int) -> bool:
        return block == 0 or self.immediate_dominators[block] is not None

    def dominates(self, dominator: int, block: int) -> bool:
        current: int | None = block
        while current is not None:
            if current == dominator:
                return True
            current = self.immediate_dominators[current]
        return False


def control_flow(function: Function) -> ControlFlow:
    count = len(function.blocks)
    successor_lists = tuple(successors(block.terminator) for block in function.blocks)
    predecessor_lists: list[list[int]] = [[] for _ in range(count)]
    for block_id, targets in enumerate(successor_lists):
        for target in targets:
            predecessor_lists[target].append(block_id)
    order = _reverse_postorder(successor_lists)
    return ControlFlow(
        successors=successor_lists,
        predecessors=tuple(tuple(sorted(items)) for items in predecessor_lists),
        reverse_postorder=order,
        immediate_dominators=_dominators(order, predecessor_lists, count),
    )


def immediate_post_dominators(
    function: Function, ignore: Container[int] = ()
) -> tuple[int | None, ...]:
    """Each block's nearest strict post-dominator.

    None when only the virtual exit post-dominates a block (paths leave the function
    separately) or when the block cannot reach an exit at all.

    Blocks in `ignore` are left out of the graph entirely. A branch whose one side calls
    `exit` has no post-dominator among the blocks that follow it, because that side never
    follows anything; ignoring it says what the two sides have in common when they do
    both come back.
    """
    count = len(function.blocks)
    # Node 0 of the reversed graph is a virtual exit following every exiting block; node
    # b + 1 is block b.
    reversed_successors: list[list[int]] = [[] for _ in range(count + 1)]
    reversed_predecessors: list[list[int]] = [[] for _ in range(count + 1)]
    for block in function.blocks:
        if block.id in ignore:
            continue
        targets = [target for target in successors(block.terminator) if target not in ignore]
        if not targets:
            reversed_successors[0].append(block.id + 1)
            reversed_predecessors[block.id + 1].append(0)
        for target in targets:
            reversed_successors[target + 1].append(block.id + 1)
            reversed_predecessors[block.id + 1].append(target + 1)
    order = _reverse_postorder(tuple(tuple(items) for items in reversed_successors))
    dominators = _dominators(order, reversed_predecessors, count + 1)
    return tuple(
        None if dominator is None or dominator == 0 else dominator - 1
        for dominator in dominators[1:]
    )


def _reverse_postorder(successor_lists: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    if not successor_lists:
        return ()
    visited = {0}
    postorder: list[int] = []
    stack: list[tuple[int, int]] = [(0, 0)]
    while stack:
        block, index = stack.pop()
        targets = successor_lists[block]
        if index < len(targets):
            stack.append((block, index + 1))
            if targets[index] not in visited:
                visited.add(targets[index])
                stack.append((targets[index], 0))
        else:
            postorder.append(block)
    return tuple(reversed(postorder))


def _dominators(
    order: tuple[int, ...], predecessor_lists: list[list[int]], count: int
) -> tuple[int | None, ...]:
    """Cooper, Harvey & Kennedy, "A Simple, Fast Dominance Algorithm"."""
    unknown = -1
    position = {block: index for index, block in enumerate(order)}
    idom = [unknown] * count
    if not order:
        return tuple(None for _ in idom)
    idom[0] = 0
    changed = True
    while changed:
        changed = False
        for block in order[1:]:
            new = unknown
            for predecessor in predecessor_lists[block]:
                if idom[predecessor] == unknown:
                    continue
                new = (
                    predecessor if new == unknown else _intersect(predecessor, new, idom, position)
                )
            if new != unknown and idom[block] != new:
                idom[block] = new
                changed = True
    return tuple(
        None if block == 0 or dominator == unknown else dominator
        for block, dominator in enumerate(idom)
    )


def _intersect(left: int, right: int, idom: list[int], position: dict[int, int]) -> int:
    while left != right:
        while position[left] > position[right]:
            left = idom[left]
        while position[right] > position[left]:
            right = idom[right]
    return left

"""Acyclic branch regions whose paths can be executed separately and merged.

A branch whose successors all meet again at its immediate post-dominator, through blocks
that form no loop and make no calls, can be explored to that join and its states merged
into one: values that differ become if-then-else expressions over the path conditions.
Loops of such diamonds (a per-character transform, say) then cost one state per
iteration instead of one per combination of choices.
"""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.ir.cfg import immediate_post_dominators
from ppy_rev.ir.model import (
    Branch,
    Call,
    Function,
    IndirectJump,
    Jump,
    successors,
)

MAX_REGION_BLOCKS = 32


@dataclass(frozen=True, slots=True)
class MergeRegion:
    branch: int
    join: int
    blocks: frozenset[int]
    """Blocks strictly between the branch and the join."""


class RegionFinder:
    def __init__(self, max_blocks: int = MAX_REGION_BLOCKS) -> None:
        self.max_blocks = max_blocks
        self._post_dominators: dict[int, tuple[int | None, ...]] = {}
        self._regions: dict[tuple[int, int], MergeRegion | None] = {}

    def region(self, function: Function, branch: int) -> MergeRegion | None:
        key = (function.entry, branch)
        if key not in self._regions:
            self._regions[key] = self._find(function, branch)
        return self._regions[key]

    def _find(self, function: Function, branch: int) -> MergeRegion | None:
        post_dominators = self._post_dominators.get(function.entry)
        if post_dominators is None:
            post_dominators = immediate_post_dominators(function)
            self._post_dominators[function.entry] = post_dominators
        join = post_dominators[branch]
        if join is None:
            return None
        blocks: set[int] = set()
        work = list(successors(function.blocks[branch].terminator))
        while work:
            block_id = work.pop()
            if block_id == join or block_id in blocks:
                continue
            if block_id == branch or len(blocks) >= self.max_blocks:
                return None
            block = function.blocks[block_id]
            if not isinstance(block.terminator, Jump | Branch | IndirectJump) or any(
                isinstance(operation, Call) for operation in block.operations
            ):
                return None
            blocks.add(block_id)
            work.extend(successors(block.terminator))
        if not _acyclic(function, blocks):
            return None
        return MergeRegion(branch, join, frozenset(blocks))


def _acyclic(function: Function, blocks: set[int]) -> bool:
    done: set[int] = set()
    active: set[int] = set()

    def visit(block_id: int) -> bool:
        if block_id in done:
            return True
        if block_id in active:
            return False
        active.add(block_id)
        for target in successors(function.blocks[block_id].terminator):
            if target in blocks and not visit(target):
                return False
        active.discard(block_id)
        done.add(block_id)
        return True

    return all(visit(block_id) for block_id in sorted(blocks))

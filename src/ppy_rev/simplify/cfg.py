"""Control-flow cleanup: constant branches, unreachable blocks, trivial phis, block merging."""

from __future__ import annotations

from dataclasses import replace

from ppy_rev.ir.cfg import control_flow
from ppy_rev.ir.model import (
    Block,
    Branch,
    Const,
    Function,
    IndirectJump,
    Jump,
    Operand,
    Phi,
    Terminator,
)
from ppy_rev.ir.transform import substitute


def simplify_cfg(function: Function) -> Function:
    while True:
        simplified = _merge_blocks(_remove_unreachable(_fold_branches(function)))
        if simplified == function:
            return function
        function = simplified


def _fold_branches(function: Function) -> Function:
    blocks: list[Block] = []
    for block in function.blocks:
        terminator = block.terminator
        if isinstance(terminator, Branch):
            if isinstance(terminator.condition, Const):
                taken = terminator.condition.value != 0
                target = terminator.true_target if taken else terminator.false_target
                block = replace(block, terminator=Jump(target, terminator.origin))
            elif terminator.true_target == terminator.false_target:
                block = replace(block, terminator=Jump(terminator.true_target, terminator.origin))
        blocks.append(block)
    return _prune_phis(replace(function, blocks=tuple(blocks)))


def _prune_phis(function: Function) -> Function:
    """Drop phi inputs from edges that no longer exist; replace phis left with one value."""
    flow = control_flow(function)
    replacements: dict[int, Operand] = {}
    blocks: list[Block] = []
    for block in function.blocks:
        predecessors = set(flow.predecessors[block.id])
        phis: list[Phi] = []
        for phi in block.phis:
            incoming = tuple((pred, value) for pred, value in phi.incoming if pred in predecessors)
            distinct = {value for _, value in incoming} - {phi.output}
            if len(distinct) == 1 and flow.reachable(block.id):
                replacements[phi.output.id] = distinct.pop()
            else:
                phis.append(replace(phi, incoming=incoming))
        blocks.append(replace(block, phis=tuple(phis)))
    return substitute(replace(function, blocks=tuple(blocks)), replacements)


def _remove_unreachable(function: Function) -> Function:
    flow = control_flow(function)
    kept = [block for block in function.blocks if flow.reachable(block.id)]
    if len(kept) == len(function.blocks):
        return function
    numbering = {block.id: index for index, block in enumerate(kept)}
    return _prune_phis(
        replace(
            function,
            blocks=tuple(
                replace(
                    block,
                    id=numbering[block.id],
                    phis=tuple(
                        replace(
                            phi,
                            incoming=tuple(
                                (numbering[pred], value)
                                for pred, value in phi.incoming
                                if pred in numbering
                            ),
                        )
                        for phi in block.phis
                    ),
                    terminator=_retarget(block.terminator, numbering),
                )
                for block in kept
            ),
        )
    )


def _retarget(terminator: Terminator, numbering: dict[int, int]) -> Terminator:
    match terminator:
        case Jump():
            return replace(terminator, target=numbering[terminator.target])
        case Branch():
            return replace(
                terminator,
                true_target=numbering[terminator.true_target],
                false_target=numbering[terminator.false_target],
            )
        case IndirectJump():
            return replace(
                terminator,
                targets=tuple((address, numbering[block]) for address, block in terminator.targets),
            )
        case _:
            return terminator


def _merge_blocks(function: Function) -> Function:
    """Append a block to its only predecessor when that predecessor jumps straight to it."""
    flow = control_flow(function)
    for block in function.blocks:
        terminator = block.terminator
        if not isinstance(terminator, Jump):
            continue
        target = function.blocks[terminator.target]
        if target.id in (0, block.id) or flow.predecessors[target.id] != (block.id,):
            continue
        if target.phis:
            continue
        offset = len(block.operations)
        merged = replace(
            block,
            operations=block.operations + target.operations,
            terminator=target.terminator,
            instructions=block.instructions
            + tuple(
                replace(start, position=start.position + offset) for start in target.instructions
            ),
        )
        blocks = [merged if other.id == block.id else other for other in function.blocks]
        # Successors of the absorbed block now see the merged block as their predecessor.
        blocks = [
            replace(
                other,
                phis=tuple(
                    replace(
                        phi,
                        incoming=tuple(
                            sorted(
                                (
                                    (block.id if pred == target.id else pred, value)
                                    for pred, value in phi.incoming
                                ),
                                key=lambda item: item[0],
                            )
                        ),
                    )
                    for phi in other.phis
                ),
            )
            for other in blocks
        ]
        return _remove_unreachable(replace(function, blocks=tuple(blocks)))
    return function

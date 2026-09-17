"""Removal of unused side-effect-free operations and phis.

Loads and divisions that may fault are kept even when unused: removing them could turn a
faulting execution into a successful one.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import replace

from ppy_rev.ir.model import (
    DIVISION_OPCODES,
    BinaryOp,
    Block,
    Const,
    Function,
    Operation,
    Piece,
    Subpiece,
    UnaryOp,
    Var,
    operation_inputs,
    terminator_inputs,
)


def is_removable(operation: Operation) -> bool:
    """Side-effect free and unable to fault."""
    match operation:
        case BinaryOp():
            if operation.opcode in DIVISION_OPCODES:
                return isinstance(operation.right, Const) and operation.right.value != 0
            return True
        case UnaryOp() | Subpiece() | Piece():
            return True
        case _:
            return False


def eliminate_dead_code(function: Function) -> Function:
    uses: Counter[int] = Counter()
    for block in function.blocks:
        for phi in block.phis:
            uses.update(value.id for _, value in phi.incoming if isinstance(value, Var))
        for operation in block.operations:
            uses.update(value.id for value in operation_inputs(operation) if isinstance(value, Var))
        uses.update(
            value.id for value in terminator_inputs(block.terminator) if isinstance(value, Var)
        )
    dead: set[int] = set()
    changed = True
    while changed:
        changed = False
        for block in function.blocks:
            for phi in block.phis:
                if phi.output.id not in dead and uses[phi.output.id] == 0:
                    dead.add(phi.output.id)
                    uses.subtract(v.id for _, v in phi.incoming if isinstance(v, Var))
                    changed = True
            for operation in block.operations:
                if not is_removable(operation):
                    continue
                (output,) = _outputs(operation)
                if output.id not in dead and uses[output.id] == 0:
                    dead.add(output.id)
                    uses.subtract(v.id for v in operation_inputs(operation) if isinstance(v, Var))
                    changed = True
    if not dead:
        return function
    return replace(function, blocks=tuple(_prune(block, dead) for block in function.blocks))


def _outputs(operation: Operation) -> tuple[Var, ...]:
    match operation:
        case BinaryOp() | UnaryOp() | Subpiece() | Piece():
            return (operation.output,)
        case _:
            return ()


def _prune(block: Block, dead: set[int]) -> Block:
    positions: list[int] = []
    operations: list[Operation] = []
    for operation in block.operations:
        positions.append(len(operations))
        outputs = _outputs(operation)
        if is_removable(operation) and outputs and outputs[0].id in dead:
            continue
        operations.append(operation)
    positions.append(len(operations))
    return replace(
        block,
        phis=tuple(phi for phi in block.phis if phi.output.id not in dead),
        operations=tuple(operations),
        instructions=tuple(
            replace(start, position=positions[start.position]) for start in block.instructions
        ),
    )

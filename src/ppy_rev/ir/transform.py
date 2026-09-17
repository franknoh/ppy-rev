"""Structural rewriting helpers shared by the lifter and simplification passes."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace

from ppy_rev.ir.model import (
    BinaryOp,
    Block,
    Branch,
    Call,
    Const,
    Function,
    Halt,
    IndirectJump,
    IndirectTarget,
    Jump,
    Load,
    Operand,
    Operation,
    Phi,
    Piece,
    Return,
    Stop,
    Store,
    Subpiece,
    TailCall,
    Terminator,
    UnaryOp,
    Unsupported,
    UserOp,
    Var,
    operation_output,
)

type Use = Callable[[Operand], Operand]
type Define = Callable[[Var], Var]


def _same(var: Var) -> Var:
    return var


def map_operation(operation: Operation, use: Use, define: Define = _same) -> Operation:
    match operation:
        case BinaryOp():
            return BinaryOp(
                operation.opcode,
                define(operation.output),
                use(operation.left),
                use(operation.right),
                operation.origin,
            )
        case UnaryOp():
            return UnaryOp(
                operation.opcode, define(operation.output), use(operation.operand), operation.origin
            )
        case Subpiece():
            return Subpiece(
                define(operation.output),
                use(operation.operand),
                operation.low_bit,
                operation.origin,
            )
        case Piece():
            return Piece(
                define(operation.output), use(operation.high), use(operation.low), operation.origin
            )
        case Load():
            return Load(define(operation.output), use(operation.address), operation.origin)
        case Store():
            return Store(use(operation.address), use(operation.value), operation.origin)
        case Call():
            return map_call(operation, use, define)
        case UserOp():
            return UserOp(
                operation.name,
                None if operation.output is None else define(operation.output),
                tuple(use(value) for value in operation.inputs),
                operation.origin,
            )
        case Unsupported():
            return Unsupported(
                operation.pcode_opcode,
                None if operation.output is None else define(operation.output),
                tuple(use(value) for value in operation.inputs),
                operation.reason,
                operation.origin,
            )


def map_call(call: Call, use: Use, define: Define = _same) -> Call:
    target = call.target
    if isinstance(target, IndirectTarget):
        target = IndirectTarget(use(target.address), target.candidates)
    return Call(
        target,
        call.argument_registers,
        tuple(use(argument) for argument in call.arguments),
        call.result_registers,
        tuple(define(result) for result in call.results),
        call.origin,
    )


def map_terminator(terminator: Terminator, use: Use, define: Define = _same) -> Terminator:
    match terminator:
        case Branch():
            return Branch(
                use(terminator.condition),
                terminator.true_target,
                terminator.false_target,
                terminator.origin,
            )
        case IndirectJump():
            return IndirectJump(use(terminator.address), terminator.targets, terminator.origin)
        case Return():
            return Return(
                tuple(use(value) for value in terminator.values),
                None if terminator.return_address is None else use(terminator.return_address),
                terminator.origin,
            )
        case TailCall():
            call = map_call(terminator.call, use, define)
            results = {
                old.id: new for old, new in zip(terminator.call.results, call.results, strict=True)
            }
            values = tuple(
                results[value.id] if isinstance(value, Var) and value.id in results else use(value)
                for value in terminator.values
            )
            return TailCall(call, values, terminator.origin)
        case Jump() | Halt() | Stop():
            return terminator


def map_phi(phi: Phi, use: Use, define: Define = _same) -> Phi:
    return Phi(define(phi.output), tuple((block, use(value)) for block, value in phi.incoming))


def resolver(replacements: Mapping[int, Operand]) -> Use:
    """Resolve operands through a replacement map, following chains."""

    def use(operand: Operand) -> Operand:
        seen = 0
        while isinstance(operand, Var) and operand.id in replacements:
            operand = replacements[operand.id]
            seen += 1
            if seen > len(replacements):
                raise ValueError("cyclic value replacement")
        return operand

    return use


def substitute(function: Function, replacements: Mapping[int, Operand]) -> Function:
    """Replace uses of values; definitions are left alone."""
    if not replacements:
        return function
    use = resolver(replacements)
    return replace(
        function,
        blocks=tuple(
            replace(
                block,
                phis=tuple(map_phi(phi, use) for phi in block.phis),
                operations=tuple(map_operation(op, use) for op in block.operations),
                terminator=map_terminator(block.terminator, use),
            )
            for block in function.blocks
        ),
    )


def renumber(function: Function) -> Function:
    """Assign dense value ids in definition order: inputs, then each block's phis and ops."""
    numbering: dict[int, int] = {}

    def assign(var: Var) -> None:
        if var.id not in numbering:
            numbering[var.id] = len(numbering)

    for item in function.inputs:
        assign(item.value)
    for block in function.blocks:
        for phi in block.phis:
            assign(phi.output)
        for operation in block.operations:
            for output in operation_output(operation):
                assign(output)
        if isinstance(block.terminator, TailCall):
            for result in block.terminator.call.results:
                assign(result)

    def use(operand: Operand) -> Operand:
        if isinstance(operand, Const):
            return operand
        return Var(numbering[operand.id], operand.width)

    def define(var: Var) -> Var:
        return Var(numbering[var.id], var.width)

    return replace(
        function,
        inputs=tuple(replace(item, value=define(item.value)) for item in function.inputs),
        blocks=tuple(
            Block(
                id=block.id,
                address=block.address,
                phis=tuple(map_phi(phi, use, define) for phi in block.phis),
                operations=tuple(map_operation(op, use, define) for op in block.operations),
                terminator=map_terminator(block.terminator, use, define),
                instructions=block.instructions,
            )
            for block in function.blocks
        ),
    )

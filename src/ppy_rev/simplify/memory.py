"""Block-local load and store forwarding.

Addresses are compared in a canonical `base + offset` form, where `base` is an SSA value
(or absent for absolute addresses) and `offset` wraps at the pointer width. Two accesses
with the same base are equal or provably disjoint by offset; accesses with different bases
may alias, so a store through one invalidates everything known about the other. Calls and
unmodeled operations may write anywhere and clear all knowledge.

A load is replaced only by the value of an earlier access to the same bytes, so it could
not have faulted where that access did not (a successful write implies the bytes are
readable, as on every supported target).
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Block,
    Call,
    Const,
    Endianness,
    Function,
    Load,
    Operand,
    Operation,
    Store,
    UnaryOp,
    UnaryOpcode,
    Unsupported,
    UserOp,
    mask,
)
from ppy_rev.ir.transform import Use, map_operation, resolver, substitute


@dataclass(frozen=True, slots=True)
class CanonicalAddress:
    base: int | None
    offset: int


@dataclass(frozen=True, slots=True)
class _Fact:
    address: CanonicalAddress
    width: int
    value: Operand


def forward_memory(function: Function, endianness: Endianness, pointer_width: int) -> Function:
    if endianness is not Endianness.LITTLE:
        return function
    definitions = {
        operation.output.id: operation
        for block in function.blocks
        for operation in block.operations
        if isinstance(operation, BinaryOp)
    }
    replacements: dict[int, Operand] = {}
    use = resolver(replacements)
    blocks = tuple(
        _forward_block(block, definitions, replacements, use, pointer_width)
        for block in function.blocks
    )
    if not replacements and blocks == function.blocks:
        return function
    return substitute(replace(function, blocks=blocks), replacements)


def _forward_block(
    block: Block,
    definitions: dict[int, BinaryOp],
    replacements: dict[int, Operand],
    use: Use,
    pointer_width: int,
) -> Block:
    facts: list[_Fact] = []
    operations: list[Operation] = []
    positions: list[int] = []
    for operation in block.operations:
        positions.append(len(operations))
        current = map_operation(operation, use)
        match current:
            case Load(output=output, address=address):
                key = canonical_address(address, definitions, pointer_width)
                known = next(
                    (fact for fact in reversed(facts) if _covers(fact, key, output.width)), None
                )
                if known is not None and known.width == output.width:
                    replacements[output.id] = known.value
                    continue
                if known is not None:
                    current = UnaryOp(UnaryOpcode.TRUNCATE, output, known.value, current.origin)
                facts.append(_Fact(key, output.width, output))
            case Store(address=address, value=value):
                key = canonical_address(address, definitions, pointer_width)
                facts = [
                    fact
                    for fact in facts
                    if _disjoint(fact.address, fact.width, key, value.width, pointer_width)
                ]
                facts.append(_Fact(key, value.width, value))
            case Call() | UserOp() | Unsupported():
                facts = []
            case _:
                pass
        operations.append(current)
    positions.append(len(operations))
    return replace(
        block,
        operations=tuple(operations),
        instructions=tuple(
            replace(start, position=positions[start.position]) for start in block.instructions
        ),
    )


def canonical_address(
    address: Operand, definitions: dict[int, BinaryOp], width: int
) -> CanonicalAddress:
    offset = 0
    current = address
    while not isinstance(current, Const):
        definition = definitions.get(current.id)
        if (
            definition is None
            or definition.opcode not in (BinaryOpcode.ADD, BinaryOpcode.SUB)
            or not isinstance(definition.right, Const)
        ):
            return CanonicalAddress(current.id, offset & mask(width))
        delta = definition.right.value
        offset += delta if definition.opcode is BinaryOpcode.ADD else -delta
        current = definition.left
    return CanonicalAddress(None, (offset + current.value) & mask(width))


def _covers(fact: _Fact, address: CanonicalAddress, width: int) -> bool:
    return fact.address == address and fact.width >= width


def _disjoint(
    first: CanonicalAddress,
    first_width: int,
    second: CanonicalAddress,
    second_width: int,
    pointer_width: int,
) -> bool:
    if first.base != second.base:
        return False
    distance = (second.offset - first.offset) & mask(pointer_width)
    return distance >= first_width // 8 and (1 << pointer_width) - distance >= second_width // 8

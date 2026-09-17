"""Memory locations as a base plus a constant offset, comparable across a function.

A base is a constant (offset from zero), a value computed in the function, or the value
loaded from another location. Keying loaded bases by where they were loaded from makes
`[rbp-0x18]->pc` the same location in every block that reloads the pointer, as unoptimized
code does.
"""

from __future__ import annotations

from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Const,
    Function,
    Load,
    Operand,
    Operation,
    Phi,
    UnaryOp,
    UnaryOpcode,
    mask,
    operation_output,
)

type Base = tuple[str, int] | tuple[str, "Location", int]
type Location = tuple[Base, int]

CONSTANT: Base = ("const", 0)


def definitions(function: Function) -> dict[int, Phi | Operation]:
    found: dict[int, Phi | Operation] = {}
    for block in function.blocks:
        for phi in block.phis:
            found[phi.output.id] = phi
        for operation in block.operations:
            for output in operation_output(operation):
                found[output.id] = operation
    return found


class Locations:
    def __init__(self, function: Function, known: dict[int, Phi | Operation] | None = None):
        self.function = function
        self.definitions = known if known is not None else definitions(function)
        self._cache: dict[int, Location] = {}
        self._inputs = {item.value.id: item.register for item in function.inputs}

    def of(self, operand: Operand) -> Location:
        if isinstance(operand, Const):
            return (CONSTANT, operand.value)
        known = self._cache.get(operand.id)
        if known is not None:
            return known
        definition = self.definitions.get(operand.id)
        result: Location
        match definition:
            case BinaryOp(
                opcode=BinaryOpcode.ADD | BinaryOpcode.SUB, left=left, right=Const(value=delta)
            ):
                base, offset = self.of(left)
                sign = 1 if definition.opcode is BinaryOpcode.ADD else -1
                result = (base, (offset + sign * delta) & mask(definition.output.width))
            case UnaryOp(opcode=UnaryOpcode.ZERO_EXTEND, operand=inner):
                result = self.of(inner)  # the same number, so the same address
            case Load(address=address):
                result = (("load", self.of(address), definition.output.width), 0)
            case _:
                result = (("value", operand.id), 0)
        self._cache[operand.id] = result
        return result

    def describe(self, location: Location) -> str:
        base, offset = location
        match base:
            case ("const", _):
                return f"{offset:#x}"
            case ("value", int() as identifier):
                text = self._inputs.get(identifier, f"v{identifier}")
            case ("load", tuple() as inner, int() as width):
                text = f"[{self.describe(inner)}]:{width}"
            case _:
                text = "?"
        return with_offset(text, offset)


def with_offset(text: str, offset: int) -> str:
    if not offset:
        return text
    if offset >= 1 << 63:
        return f"{text}-{(1 << 64) - offset:#x}"
    return f"{text}+{offset:#x}"

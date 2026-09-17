"""Construct RevIR directly, for tests of passes that should not depend on the lifter."""

from __future__ import annotations

from dataclasses import dataclass, field

from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Block,
    Endianness,
    Function,
    FunctionInput,
    Load,
    Module,
    Operand,
    Operation,
    Origin,
    Piece,
    Register,
    Return,
    Store,
    Subpiece,
    Target,
    Terminator,
    UnaryOp,
    UnaryOpcode,
    Var,
)

ORIGIN = Origin(0x1000, 0)


@dataclass
class BlockBuilder:
    function: FunctionBuilder
    id: int
    operations: list[Operation] = field(default_factory=list[Operation])

    def binary(self, opcode: BinaryOpcode, left: Operand, right: Operand, width: int = 0) -> Var:
        output = self.function.var(width or left.width)
        self.operations.append(BinaryOp(opcode, output, left, right, ORIGIN))
        return output

    def unary(self, opcode: UnaryOpcode, operand: Operand, width: int = 0) -> Var:
        output = self.function.var(width or operand.width)
        self.operations.append(UnaryOp(opcode, output, operand, ORIGIN))
        return output

    def subpiece(self, operand: Operand, low_bit: int, width: int) -> Var:
        output = self.function.var(width)
        self.operations.append(Subpiece(output, operand, low_bit, ORIGIN))
        return output

    def piece(self, high: Operand, low: Operand) -> Var:
        output = self.function.var(high.width + low.width)
        self.operations.append(Piece(output, high, low, ORIGIN))
        return output

    def load(self, address: Operand, width: int) -> Var:
        output = self.function.var(width)
        self.operations.append(Load(output, address, ORIGIN))
        return output

    def store(self, address: Operand, value: Operand) -> None:
        self.operations.append(Store(address, value, ORIGIN))


class FunctionBuilder:
    def __init__(self, inputs: list[tuple[str, int]]) -> None:
        self._next = 0
        self.inputs = tuple(FunctionInput(name, self.var(width)) for name, width in inputs)
        self.blocks: list[BlockBuilder] = []
        self.terminators: dict[int, Terminator] = {}

    def var(self, width: int) -> Var:
        self._next += 1
        return Var(self._next, width)

    def input(self, name: str) -> Var:
        return next(item.value for item in self.inputs if item.register == name)

    def block(self) -> BlockBuilder:
        builder = BlockBuilder(self, len(self.blocks))
        self.blocks.append(builder)
        return builder

    def finish(self, outputs: tuple[str, ...], name: str = "f") -> Function:
        return Function(
            name=name,
            entry=0x1000,
            inputs=self.inputs,
            output_registers=outputs,
            blocks=tuple(
                Block(block.id, 0x1000, (), tuple(block.operations), self.terminators[block.id])
                for block in self.blocks
            ),
        )

    def returns(self, block: BlockBuilder, *values: Operand) -> None:
        self.terminators[block.id] = Return(values, None, ORIGIN)


def module_for(*functions: Function, registers: tuple[tuple[str, int], ...]) -> Module:
    return Module(
        name="test",
        target=Target("x86-64", Endianness.LITTLE, 64, "RSP", "RIP"),
        registers=tuple(
            Register(name, index * 0x100, width) for index, (name, width) in enumerate(registers)
        ),
        memory=(),
        externals=(),
        functions=functions,
        labels=(),
    )

"""Build synthetic Ghidra exports for tests that should not need Ghidra.

Registers follow Ghidra's x86-64 layout so p-code written here reads like real output.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from ppy_rev.ghidra.schema import (
    BinaryInfo,
    Function,
    GhidraExport,
    Instruction,
    MemoryBlock,
    PcodeOp,
    Producer,
    Register,
    ReturnValue,
    Symbol,
    ThunkTarget,
    Varnode,
)

REGISTERS = (
    ("RAX", 0x0, 8, "RAX"),
    ("EAX", 0x0, 4, "RAX"),
    ("AX", 0x0, 2, "RAX"),
    ("AL", 0x0, 1, "RAX"),
    ("AH", 0x1, 1, "RAX"),
    ("RCX", 0x8, 8, "RCX"),
    ("ECX", 0x8, 4, "RCX"),
    ("CL", 0x8, 1, "RCX"),
    ("RDX", 0x10, 8, "RDX"),
    ("EDX", 0x10, 4, "RDX"),
    ("RSP", 0x20, 8, "RSP"),
    ("RBP", 0x28, 8, "RBP"),
    ("RSI", 0x30, 8, "RSI"),
    ("ESI", 0x30, 4, "RSI"),
    ("RDI", 0x38, 8, "RDI"),
    ("EDI", 0x38, 4, "RDI"),
    ("CF", 0x200, 1, "CF"),
    ("ZF", 0x206, 1, "ZF"),
    ("SF", 0x207, 1, "SF"),
    ("OF", 0x20B, 1, "OF"),
    ("RIP", 0x288, 8, "RIP"),
)
_BY_NAME = {name: (offset, size) for name, offset, size, _ in REGISTERS}


def reg(name: str) -> Varnode:
    offset, size = _BY_NAME[name]
    return Varnode("register", offset, size)


def const(value: int, size: int) -> Varnode:
    return Varnode("const", value & ((1 << (size * 8)) - 1), size)


def ram(address: int, size: int = 8) -> Varnode:
    return Varnode("ram", address, size)


def tmp(offset: int, size: int) -> Varnode:
    return Varnode("unique", offset, size)


def op(
    opcode: str,
    inputs: list[Varnode],
    output: Varnode | None = None,
    *,
    memory_space: str | None = None,
    user_op: str | None = None,
) -> PcodeOp:
    if opcode in ("LOAD", "STORE"):
        memory_space = memory_space or "ram"
        inputs = [const(0x1B1, 8), *inputs]
    return PcodeOp(opcode, tuple(inputs), output, memory_space, user_op)


def ret() -> list[PcodeOp]:
    """x86-64 `RET`: pop the return address into RIP and return through it."""
    return [
        op("LOAD", [reg("RSP")], reg("RIP")),
        op("INT_ADD", [reg("RSP"), const(8, 8)], reg("RSP")),
        op("RETURN", [reg("RIP")]),
    ]


def call(target: int, return_address: int) -> list[PcodeOp]:
    return [
        op("INT_SUB", [reg("RSP"), const(8, 8)], reg("RSP")),
        op("STORE", [reg("RSP"), const(return_address, 8)]),
        op("CALL", [ram(target)]),
    ]


@dataclass
class ProgramBuilder:
    image_base: int = 0x400000
    instructions: dict[int, Instruction] = field(default_factory=dict[int, Instruction])
    functions: list[Function] = field(default_factory=list[Function])
    blocks: list[MemoryBlock] = field(default_factory=list[MemoryBlock])
    symbols: list[Symbol] = field(default_factory=list[Symbol])

    def code(self, address: int, pcode: list[PcodeOp], length: int = 4, text: str = "") -> int:
        """Add an instruction; returns the address of the next one."""
        flows = tuple(
            item.inputs[0].offset
            for item in pcode
            if item.opcode in ("BRANCH", "CBRANCH", "CALL") and item.inputs[0].space == "ram"
        )
        self.instructions[address] = Instruction(
            address=address,
            length=length,
            data=bytes(length),
            mnemonic=text.split(" ")[0] if text else "INSN",
            text=text or "INSN",
            flow="FALL_THROUGH",
            fallthrough=address + length,
            flows=flows,
            references=(),
            pcode=tuple(pcode),
        )
        return address + length

    def indirect_flows(self, address: int, targets: tuple[int, ...]) -> None:
        self.instructions[address] = replace(self.instructions[address], flows=targets)

    def function(
        self,
        name: str,
        entry: int,
        *,
        no_return: bool = False,
        thunk: ThunkTarget | None = None,
    ) -> None:
        self.functions.append(
            Function(
                name=name,
                entry=entry,
                no_return=no_return,
                calling_convention="__stdcall",
                signature=f"undefined {name}()",
                signature_source="DEFAULT",
                varargs=False,
                thunk_target=thunk,
                parameters=(),
                returns=ReturnValue("undefined", 1, ()),
                body=(),
                blocks=(),
                high=None,
            )
        )

    def import_(self, name: str, stub: int, *, no_return: bool = False) -> None:
        self.function(
            name, stub, no_return=no_return, thunk=ThunkTarget(name, external=True, address=1)
        )

    def symbol(self, name: str, address: int) -> None:
        """A named address, as Ghidra reports one; outside every block it is an import."""
        self.symbols.append(
            Symbol(
                name=name,
                qualified_name=name,
                kind="label",
                source="imported",
                external=False,
                primary=True,
                entry_point=False,
                address=address,
            )
        )

    def data(self, name: str, start: int, content: bytes, *, writable: bool = False) -> None:
        self.blocks.append(
            MemoryBlock(
                name=name,
                space="ram",
                start=start,
                size=len(content),
                read=True,
                write=writable,
                execute=False,
                initialized=True,
                loaded=True,
                external=False,
                artificial=False,
                data=content,
            )
        )

    def build(self) -> GhidraExport:
        return GhidraExport(
            schema_version=1,
            producer=Producer("12.1.3", decompiled=False),
            binary=BinaryInfo(
                name="synthetic",
                format="ELF",
                sha256=None,
                language="x86:LE:64:default",
                processor="x86",
                endianness="little",
                pointer_size=8,
                compiler_spec="gcc",
                image_base=self.image_base,
                program_counter="RIP",
                stack_pointer="RSP",
                entry_points=(),
            ),
            address_spaces=(),
            registers=tuple(
                Register(name, offset, size, base) for name, offset, size, base in REGISTERS
            ),
            user_ops=(),
            memory_blocks=tuple(self.blocks),
            symbols=tuple(self.symbols),
            strings=(),
            external_functions=(),
            functions=tuple(sorted(self.functions, key=lambda function: function.entry)),
            instructions=tuple(self.instructions[address] for address in sorted(self.instructions)),
        )

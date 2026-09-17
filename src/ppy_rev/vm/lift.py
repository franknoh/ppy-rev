"""Lifting a program's bytecode: from a detected dispatcher to VM-level RevIR and an ISA.

The interpreter function is entered once along some path from main (found by symbolic
exploration); the state there fixes the interpreter's pointers and program counter. The
interpreter is then specialized to its bytecode (see `ppy_rev.vm.specialize`), which
yields a RevIR function with one entry block per bytecode instruction, and a record of
each instruction: its opcode, bytes, handler, successors, and effects.

The instruction set description is built only from what the specialization observed:
opcode names stay neutral (`op_11`), and effects are the residual RevIR each instruction
instance performs, written over the interpreter's state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ppy_rev.analysis.program import calls
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.ir.model import (
    BinaryOp,
    Block,
    Branch,
    Call,
    Const,
    DirectTarget,
    Function,
    IndirectJump,
    Load,
    Module,
    Operand,
    Operation,
    Piece,
    Return,
    Store,
    Subpiece,
    UnaryOp,
    UnaryOpcode,
    Var,
    operation_output,
)
from ppy_rev.simplify.pipeline import simplify_function
from ppy_rev.solve import SolveRequest, reach
from ppy_rev.symbolic.state import State
from ppy_rev.vm.detect import LIKELY_DISPATCHER, Dispatcher, detect_dispatchers
from ppy_rev.vm.specialize import (
    EntryState,
    Guard,
    Interpreter,
    Iteration,
    MemoryCounter,
    PhiCounter,
    ProgramCounter,
    Specialization,
    specialize,
)

_EXPRESSION_DEPTH = 6


class VmLiftError(PpyRevError):
    pass


@dataclass(frozen=True, slots=True)
class Instruction:
    counter: int
    opcode: int | None
    name: str
    bytes: bytes
    handler: int | None
    successors: tuple[int, ...]
    exits: tuple[str, ...]
    effects: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OpcodeDescription:
    opcode: int
    name: str
    handler: int | None
    lengths: tuple[int, ...]
    """Byte lengths of its instances."""
    instances: int
    branches: bool
    """Some instance has more than one possible successor."""
    exits: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LiftedVm:
    dispatcher: Dispatcher
    specialization: Specialization
    function: Function
    """The bytecode as a RevIR function, simplified; it replaces the interpreter's call."""
    bytecode_base: int | None
    instructions: tuple[Instruction, ...]
    opcodes: tuple[OpcodeDescription, ...]
    guards: tuple[Guard, ...]


def lift_vm(
    module: Module, request: SolveRequest, dispatcher: Dispatcher | None = None
) -> LiftedVm:
    if dispatcher is None:
        candidates = [
            candidate
            for candidate in detect_dispatchers(module)
            if candidate.confidence >= LIKELY_DISPATCHER
        ]
        if not candidates:
            raise VmLiftError("no VM dispatcher found (see `ppy-rev vm detect --all`)")
        dispatcher = candidates[0]
    function = module.function_at(dispatcher.function_entry)
    if function is None or dispatcher.loop_header is None or dispatcher.fetch is None:
        raise VmLiftError("the dispatcher has no dispatch loop or opcode fetch to follow")
    interpreter = Interpreter(
        function=function,
        loop_header=_block_at(function, dispatcher.loop_header),
        counter=_counter(dispatcher, function, _block_at(function, dispatcher.loop_header)),
        fetches=frozenset(dispatcher.fetch.instructions),
        handlers=frozenset(handler.block for handler in dispatcher.handlers),
    )
    entry_block = function.blocks[0]
    # An instruction without p-code (endbr64) has no start of its own to stop at.
    first = entry_block.instructions[0].address if entry_block.instructions else entry_block.address
    state = reach(module, request, first)
    if state is None:
        raise VmLiftError(f"no path from main reaches the interpreter {function.name}")
    specialization = specialize(module, interpreter, _entry_state(state))
    simplified = simplify_function(module, specialization.function)
    counter_address = _counter_address(specialization)
    instructions = tuple(
        _instruction(module, specialization, item, counter_address)
        for item in specialization.iterations
    )
    base = specialization.bytecode_base
    return LiftedVm(
        dispatcher=dispatcher,
        specialization=specialization,
        function=simplified,
        bytecode_base=base,
        instructions=instructions,
        opcodes=_describe_opcodes(instructions),
        guards=specialization.guards,
    )


def patch_interpreter(module: Module, lifted: LiftedVm) -> Module:
    """`module` with calls to the interpreter redirected to the lifted bytecode function.

    The lifted function keeps the interpreter's interface; its guards stop any call made
    in a state it was not specialized for.
    """
    interpreter = lifted.dispatcher.function_entry
    address = _free_address(module)
    bytecode = replace(lifted.function, entry=address)
    functions: list[Function] = []
    for function in module.functions:
        blocks: list[Block] = []
        for block in function.blocks:
            operations = tuple(
                replace(operation, target=DirectTarget(address))
                if isinstance(operation, Call)
                and isinstance(operation.target, DirectTarget)
                and operation.target.address == interpreter
                else operation
                for operation in block.operations
            )
            blocks.append(replace(block, operations=operations))
        functions.append(replace(function, blocks=tuple(blocks)))
    functions.append(bytecode)
    return replace(module, functions=tuple(functions))


def interpreter_calls(module: Module, lifted: LiftedVm) -> int:
    return sum(
        1
        for function in module.functions
        for call, _ in calls(function)
        if isinstance(call.target, DirectTarget)
        and call.target.address == lifted.dispatcher.function_entry
    )


# -- setup ---------------------------------------------------------------------------------


def _block_at(function: Function, address: int) -> int:
    for block in function.blocks:
        if block.address == address:
            return block.id
    raise VmLiftError(f"no block at {address:#x} in {function.name}")


def _counter(dispatcher: Dispatcher, function: Function, header: int) -> ProgramCounter:
    fetch = dispatcher.fetch
    if fetch is not None and fetch.program_counter_phi is not None:
        return PhiCounter(_header_counter(function, header, fetch.program_counter_phi))
    if fetch is not None and fetch.program_counter_location is not None:
        width = 32
        if fetch.program_counter is not None and ":" in fetch.program_counter:
            width = int(fetch.program_counter.rsplit(":", 1)[1])
        return MemoryCounter(fetch.program_counter_location, width)
    raise VmLiftError("the VM program counter could not be identified")


def _header_counter(function: Function, header: int, phi: int) -> int:
    """The loop-header phi carrying the program counter held in `phi`.

    The counter may live in a phi further into the loop, reaching the header only as a
    zero-extended or truncated copy.
    """
    header_phis = function.blocks[header].phis
    if any(item.output.id == phi for item in header_phis):
        return phi
    definitions: dict[int, Operation] = {
        output.id: operation
        for block in function.blocks
        for operation in block.operations
        for output in operation_output(operation)
    }

    def copies(operand: Operand) -> bool:
        while isinstance(operand, Var):
            if operand.id == phi:
                return True
            match definitions.get(operand.id):
                case UnaryOp(opcode=opcode, operand=inner) if opcode in _COPIES:
                    operand = inner
                case _:
                    return False
        return False

    for item in header_phis:
        if any(copies(value) for _, value in item.incoming):
            return item.output.id
    raise VmLiftError("the VM program counter does not reach the dispatch loop header")


_COPIES = frozenset({UnaryOpcode.ZERO_EXTEND, UnaryOpcode.TRUNCATE})


def _entry_state(state: State) -> EntryState:
    frame = state.frame
    registers = {
        item.register: value.value
        for item in frame.function.inputs
        if (value := frame.values.get(item.value.id)) is not None and value.is_const
    }

    def memory(address: int, width: int) -> int | None:
        size = width // 8
        if not state.memory.accessible(address, size, write=False):
            return None
        value = 0
        for index in range(size):
            byte = state.memory.read_byte(address + index)
            if not byte.is_const:
                return None
            value |= byte.value << (8 * index)
        return value

    return EntryState(registers=registers.get, memory=memory)


def _free_address(module: Module) -> int:
    top = max(
        [function.entry for function in module.functions] + [region.end for region in module.memory]
    )
    return (top + 0x1000) & ~0xFFF


# -- descriptions --------------------------------------------------------------------------


def _counter_address(specialization: Specialization) -> int | None:
    """The address instructions store their successor's program counter to, if any."""
    votes: dict[int, int] = {}
    for item in specialization.iterations:
        for block_id in item.blocks:
            for operation in specialization.function.blocks[block_id].operations:
                match operation:
                    case Store(address=Const(value=address), value=Const(value=value)) if (
                        value in item.successors
                    ):
                        votes[address] = votes.get(address, 0) + 1
                    case _:
                        pass
    return max(votes, key=lambda address: votes[address]) if votes else None


def _instruction(
    module: Module, specialization: Specialization, item: Iteration, counter_address: int | None
) -> Instruction:
    raw = bytes(byte for address in item.bytecode if (byte := _byte(module, address)) is not None)
    name = "?" if item.opcode is None else f"op_{item.opcode:02x}"
    effects = _Effects(specialization, item, counter_address).render()
    return Instruction(
        counter=item.counter,
        opcode=item.opcode,
        name=name,
        bytes=raw,
        handler=item.handler,
        successors=item.successors,
        exits=item.exits,
        effects=effects,
    )


def _byte(module: Module, address: int) -> int | None:
    for region in module.memory:
        if region.data is not None and region.start <= address < region.start + len(region.data):
            return region.data[address - region.start]
    return None


def _describe_opcodes(instructions: tuple[Instruction, ...]) -> tuple[OpcodeDescription, ...]:
    grouped: dict[int, list[Instruction]] = {}
    for instruction in instructions:
        if instruction.opcode is not None:
            grouped.setdefault(instruction.opcode, []).append(instruction)
    return tuple(
        OpcodeDescription(
            opcode=opcode,
            name=f"op_{opcode:02x}",
            handler=members[0].handler,
            lengths=tuple(sorted({len(member.bytes) for member in members})),
            instances=len(members),
            branches=any(len(member.successors) > 1 for member in members),
            exits=tuple(sorted({exit_ for member in members for exit_ in member.exits})),
        )
        for opcode, members in sorted(grouped.items())
    )


class _Effects:
    """An instruction's residual code as assignments over the interpreter's memory."""

    def __init__(
        self, specialization: Specialization, item: Iteration, counter_address: int | None
    ) -> None:
        self.function = specialization.function
        self.item = item
        self.counter_address = counter_address
        self.definitions: dict[int, Operation] = {}
        for block in self.function.blocks:
            for operation in block.operations:
                for output in operation_output(operation):
                    self.definitions[output.id] = operation
        self.pointers = {
            guard.value: guard.register
            for guard in specialization.guards
            if guard.register is not None and guard.value > 0xFFFF
        }

    def render(self) -> tuple[str, ...]:
        lines: list[str] = []
        for block_id in self.item.blocks:
            block = self.function.blocks[block_id]
            for operation in block.operations:
                match operation:
                    case Store(address=Const(value=target), value=Const()) if (
                        target == self.counter_address
                    ):
                        pass  # the program counter update; successors show it
                    case Store(address=address, value=value):
                        lines.append(f"{self.address(address)} := {self.expression(value)}")
                    case Call():
                        lines.append(f"call at {operation.origin.address:#x}")
                    case _:
                        pass
            match block.terminator:
                case Branch(condition=condition):
                    lines.append(f"if {self.expression(condition)}")
                case IndirectJump(address=address):
                    lines.append(f"jump to {self.expression(address)}")
                case Return(values=values) if values:
                    rendered = ", ".join(self.expression(value) for value in values)
                    lines.append(f"return {rendered}")
                case _:
                    pass
        return tuple(dict.fromkeys(lines))

    def address(self, operand: Operand) -> str:
        if isinstance(operand, Const):
            return f"[{self.pointer(operand.value)}]"
        return f"[{self.expression(operand)}]"

    def pointer(self, value: int) -> str:
        nearest = max(
            (base for base in self.pointers if base <= value < base + 0x1000), default=None
        )
        if nearest is None:
            return f"{value:#x}"
        offset = value - nearest
        name = self.pointers[nearest]
        return name if not offset else f"{name}+{offset:#x}"

    def expression(self, operand: Operand, depth: int = _EXPRESSION_DEPTH) -> str:
        if isinstance(operand, Const):
            return f"{operand.value:#x}" if operand.value > 9 else str(operand.value)
        definition = self.definitions.get(operand.id)
        if definition is None or depth <= 0:
            return _name(operand)
        match definition:
            case Load(address=address, output=output):
                return f"{self.address(address)}:{output.width}"
            case BinaryOp(opcode=opcode, left=left, right=right):
                return (
                    f"({self.expression(left, depth - 1)} {opcode} "
                    f"{self.expression(right, depth - 1)})"
                )
            case UnaryOp(opcode=opcode, operand=inner):
                return f"{opcode}({self.expression(inner, depth - 1)})"
            case Subpiece(operand=inner, low_bit=low_bit, output=output):
                return f"{self.expression(inner, depth - 1)}[{low_bit}:{low_bit + output.width}]"
            case Piece(high=high, low=low):
                return f"({self.expression(high, depth - 1)} ++ {self.expression(low, depth - 1)})"
            case _:
                return _name(operand)


def _name(var: Var) -> str:
    return f"v{var.id}"


type JsonValue = str | int | bool | list[JsonValue] | dict[str, JsonValue] | None


def isa_description(lifted: LiftedVm) -> dict[str, JsonValue]:
    """A machine-readable description of the recovered instruction set and bytecode."""
    dispatcher = lifted.dispatcher
    return {
        "dispatcher": {
            "function": dispatcher.function,
            "address": dispatcher.address,
            "confidence": str(dispatcher.confidence),
        },
        "bytecode_base": lifted.bytecode_base,
        "guards": [guard.describe() for guard in lifted.guards],
        "opcodes": [
            {
                "opcode": item.opcode,
                "name": item.name,
                "handler": item.handler,
                "lengths": list(item.lengths),
                "instances": item.instances,
                "branches": item.branches,
                "exits": list(item.exits),
            }
            for item in lifted.opcodes
        ],
        "instructions": [
            {
                "counter": item.counter,
                "opcode": item.opcode,
                "name": item.name,
                "bytes": item.bytes.hex(),
                "successors": list(item.successors),
                "exits": list(item.exits),
                "effects": list(item.effects),
            }
            for item in lifted.instructions
        ],
    }

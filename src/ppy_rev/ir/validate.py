"""Structural validation of RevIR.

Checks what every consumer relies on: single definitions, definitions dominating uses,
width rules per operation, and consistency between phis, terminators, and the CFG.
Violations are lifter or pass bugs, so they are reported as a list of messages rather
than user-facing diagnostics.
"""

from __future__ import annotations

from ppy_rev.ir.cfg import ControlFlow, control_flow
from ppy_rev.ir.model import (
    BOOLEAN_OPCODES,
    COMPARISON_OPCODES,
    SHIFT_OPCODES,
    BinaryOp,
    Call,
    Const,
    Function,
    IndirectTarget,
    Load,
    Module,
    Operand,
    Operation,
    Piece,
    Return,
    Store,
    Subpiece,
    TailCall,
    UnaryOp,
    UnaryOpcode,
    Var,
    operation_inputs,
    operation_output,
    terminator_inputs,
)

type Definition = tuple[int, int]
"""(block id, position); inputs use block -1. Phis sit at position -1 of their block."""


def validate_module(module: Module) -> list[str]:
    problems: list[str] = []
    registers = {register.name: register.width for register in module.registers}
    for function in module.functions:
        problems.extend(
            f"{function.name}: {problem}"
            for problem in validate_function(function, registers, module.target.pointer_width)
        )
    return problems


def validate_function(
    function: Function, registers: dict[str, int], pointer_width: int
) -> list[str]:
    problems: list[str] = []
    flow = control_flow(function)
    definitions: dict[int, tuple[Definition, int]] = {}

    def define(var: Var, where: Definition) -> None:
        if var.id in definitions:
            problems.append(f"v{var.id} is defined more than once")
        definitions[var.id] = (where, var.width)

    for function_input in function.inputs:
        define(function_input.value, (-1, 0))
        expected = registers.get(function_input.register)
        if expected is not None and expected != function_input.value.width:
            problems.append(
                f"input {function_input.register} has width {function_input.value.width}"
            )
    for block in function.blocks:
        if block.id != function.blocks.index(block):
            problems.append(f"block {block.id} is out of order")
        for phi in block.phis:
            define(phi.output, (block.id, -1))
        for position, operation in enumerate(block.operations):
            for output in operation_output(operation):
                define(output, (block.id, position))
        if isinstance(block.terminator, TailCall):
            for result in block.terminator.call.results:
                define(result, (block.id, len(block.operations)))

    def check_use(operand: Operand, block: int, position: int, context: str) -> None:
        if isinstance(operand, Const):
            return
        found = definitions.get(operand.id)
        if found is None:
            problems.append(f"bb{block} {context}: v{operand.id} is never defined")
            return
        (def_block, def_position), width = found
        if width != operand.width:
            problems.append(
                f"bb{block} {context}: v{operand.id} used as {operand.width} bits, "
                f"defined as {width}"
            )
        if not _dominates(flow, def_block, def_position, block, position):
            problems.append(f"bb{block} {context}: v{operand.id} does not dominate its use")

    for block in function.blocks:
        if not flow.reachable(block.id):
            continue
        predecessors = set(flow.predecessors[block.id])
        for phi in block.phis:
            incoming = {predecessor for predecessor, _ in phi.incoming}
            if incoming != predecessors:
                problems.append(
                    f"bb{block.id} phi v{phi.output.id} covers {sorted(incoming)}, "
                    f"predecessors are {sorted(predecessors)}"
                )
            for predecessor, value in phi.incoming:
                width_ok = value.width == phi.output.width
                if not width_ok:
                    problems.append(f"bb{block.id} phi v{phi.output.id} mixes widths")
                end = len(function.blocks[predecessor].operations) + 1
                check_use(value, predecessor, end, f"phi v{phi.output.id}")
        for position, operation in enumerate(block.operations):
            for operand in operation_inputs(operation):
                check_use(operand, block.id, position, type(operation).__name__)
            problems.extend(
                f"bb{block.id} op {position}: {problem}"
                for problem in _widths(operation, registers, pointer_width)
            )
        terminator = block.terminator
        end = len(block.operations)
        if isinstance(terminator, TailCall):
            # The call's results are defined at `end` and returned right after it.
            for operand in operation_inputs(terminator.call):
                check_use(operand, block.id, end, "TailCall")
            for operand in terminator.values:
                check_use(operand, block.id, end + 1, "TailCall")
        else:
            for operand in terminator_inputs(terminator):
                check_use(operand, block.id, end, type(terminator).__name__)
        if isinstance(terminator, Return) and len(terminator.values) != len(
            function.output_registers
        ):
            problems.append(f"bb{block.id} return has {len(terminator.values)} values")
        if isinstance(terminator, TailCall):
            problems.extend(_widths(terminator.call, registers, pointer_width))
    return problems


def _dominates(
    flow: ControlFlow, def_block: int, def_position: int, use_block: int, use_position: int
) -> bool:
    if def_block == -1:
        return True
    if def_block == use_block:
        return def_position < use_position
    return flow.dominates(def_block, use_block)


def _widths(operation: Operation, registers: dict[str, int], pointer_width: int) -> list[str]:
    problems: list[str] = []
    match operation:
        case BinaryOp(opcode=opcode, output=output, left=left, right=right):
            if opcode in SHIFT_OPCODES:
                if output.width != left.width:
                    problems.append(f"{opcode} output width differs from its operand")
            elif opcode in COMPARISON_OPCODES:
                if left.width != right.width or output.width != 8:
                    problems.append(f"{opcode} widths {left.width}/{right.width}->{output.width}")
            elif opcode in BOOLEAN_OPCODES:
                if not left.width == right.width == output.width == 8:
                    problems.append(f"{opcode} operates on bytes")
            elif not left.width == right.width == output.width:
                problems.append(f"{opcode} widths {left.width}/{right.width}->{output.width}")
        case UnaryOp(opcode=opcode, output=output, operand=operand):
            match opcode:
                case UnaryOpcode.ZERO_EXTEND | UnaryOpcode.SIGN_EXTEND:
                    if output.width <= operand.width:
                        problems.append(f"{opcode} must widen")
                case UnaryOpcode.TRUNCATE:
                    if output.width >= operand.width:
                        problems.append("truncate must narrow")
                case UnaryOpcode.POPCOUNT | UnaryOpcode.COUNT_LEADING_ZEROS:
                    pass
                case UnaryOpcode.BOOLEAN_NOT:
                    if output.width != 8 or operand.width != 8:
                        problems.append("boolean_not operates on bytes")
                case UnaryOpcode.COPY | UnaryOpcode.BITWISE_NOT | UnaryOpcode.TWOS_COMPLEMENT:
                    if output.width != operand.width:
                        problems.append(f"{opcode} must preserve width")
        case Subpiece(output=output, operand=operand, low_bit=low_bit):
            if low_bit < 0 or low_bit + output.width > operand.width:
                problems.append(
                    f"subpiece of bits {low_bit}..{low_bit + output.width} "
                    f"exceeds {operand.width} bits"
                )
        case Piece(output=output, high=high, low=low):
            if output.width != high.width + low.width:
                problems.append("piece width is not the sum of its parts")
        case Load(address=address) | Store(address=address):
            if address.width != pointer_width:
                problems.append(f"memory address is {address.width} bits")
        case Call():
            if len(operation.arguments) != len(operation.argument_registers) or len(
                operation.results
            ) != len(operation.result_registers):
                problems.append("call registers and values are misaligned")
            for register, value in (
                *zip(operation.argument_registers, operation.arguments, strict=False),
                *zip(operation.result_registers, operation.results, strict=False),
            ):
                if registers.get(register) != value.width:
                    problems.append(f"call register {register} carries {value.width} bits")
            if isinstance(operation.target, IndirectTarget) and (
                operation.target.address.width != pointer_width
            ):
                problems.append("indirect call target is not pointer-sized")
        case _:
            pass
    return problems

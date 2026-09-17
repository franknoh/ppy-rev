"""Deterministic textual form of RevIR, used by `--emit-ir` and golden tests."""

from __future__ import annotations

from collections.abc import Iterator

from ppy_rev.ir.model import (
    BinaryOp,
    Block,
    Branch,
    Call,
    CallTarget,
    Const,
    DirectTarget,
    ExternalTarget,
    Function,
    Halt,
    IndirectJump,
    IndirectTarget,
    Jump,
    Load,
    Module,
    Operand,
    Operation,
    Origin,
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
)

_COMMENT_COLUMN = 56


def format_operand(operand: Operand) -> str:
    if isinstance(operand, Const):
        return f"{operand.value:#x}:{operand.width}"
    return f"v{operand.id}"


def _defines(var: Var) -> str:
    return f"v{var.id}:{var.width}"


def _origin(line: str, origin: Origin) -> str:
    return f"{line:<{_COMMENT_COLUMN}}; {origin.address:#x}:{origin.pcode_index}"


class _Printer:
    def __init__(self, module: Module) -> None:
        self.module = module
        self.function_names = {function.entry: function.name for function in module.functions}

    def target(self, target: CallTarget) -> str:
        match target:
            case DirectTarget(address=address):
                name = self.function_names.get(address)
                return f"{name}@{address:#x}" if name else f"{address:#x}"
            case ExternalTarget(name=name, address=address):
                return f"extern {name}@{address:#x}"
            case IndirectTarget(address=address, candidates=candidates):
                listed = ", ".join(f"{candidate:#x}" for candidate in candidates)
                return f"*{format_operand(address)} [{listed}]"

    def call(self, call: Call) -> str:
        arguments = ", ".join(
            f"{register}={format_operand(value)}"
            for register, value in zip(call.argument_registers, call.arguments, strict=True)
        )
        results = ", ".join(
            f"{register}={_defines(value)}"
            for register, value in zip(call.result_registers, call.results, strict=True)
        )
        return f"call {self.target(call.target)} ({arguments}) -> ({results})"

    def operation(self, operation: Operation) -> str:
        match operation:
            case BinaryOp():
                line = (
                    f"{_defines(operation.output)} = {operation.opcode} "
                    f"{format_operand(operation.left)}, {format_operand(operation.right)}"
                )
            case UnaryOp():
                line = (
                    f"{_defines(operation.output)} = {operation.opcode} "
                    f"{format_operand(operation.operand)}"
                )
            case Subpiece():
                line = (
                    f"{_defines(operation.output)} = subpiece "
                    f"{format_operand(operation.operand)}, {operation.low_bit}"
                )
            case Piece():
                line = (
                    f"{_defines(operation.output)} = piece "
                    f"{format_operand(operation.high)}, {format_operand(operation.low)}"
                )
            case Load():
                line = f"{_defines(operation.output)} = load {format_operand(operation.address)}"
            case Store():
                line = (
                    f"store {format_operand(operation.address)}, {format_operand(operation.value)}"
                )
            case Call():
                line = self.call(operation)
            case UserOp():
                prefix = "" if operation.output is None else f"{_defines(operation.output)} = "
                operands = ", ".join(format_operand(value) for value in operation.inputs)
                line = f"{prefix}userop {operation.name}({operands})"
            case Unsupported():
                prefix = "" if operation.output is None else f"{_defines(operation.output)} = "
                operands = ", ".join(format_operand(value) for value in operation.inputs)
                line = (
                    f"{prefix}unsupported {operation.pcode_opcode}({operands}) [{operation.reason}]"
                )
        return _origin(line, operation.origin)

    def terminator(self, terminator: Terminator, function: Function) -> str:
        match terminator:
            case Jump():
                line = f"jump bb{terminator.target}"
            case Branch():
                line = (
                    f"branch {format_operand(terminator.condition)}, "
                    f"bb{terminator.true_target}, bb{terminator.false_target}"
                )
            case IndirectJump():
                targets = ", ".join(
                    f"{address:#x}: bb{block}" for address, block in terminator.targets
                )
                line = f"jump_indirect {format_operand(terminator.address)} [{targets}]"
            case Return():
                values = ", ".join(
                    f"{register}={format_operand(value)}"
                    for register, value in zip(
                        function.output_registers, terminator.values, strict=True
                    )
                )
                via = (
                    ""
                    if terminator.return_address is None
                    else f" via {format_operand(terminator.return_address)}"
                )
                line = f"return ({values}){via}"
            case TailCall():
                line = f"tail_{self.call(terminator.call)}"
            case Halt():
                line = "halt"
            case Stop():
                line = f"stop [{terminator.reason}]"
        return _origin(line, terminator.origin)

    def block(self, block: Block, function: Function) -> Iterator[str]:
        yield f"  bb{block.id} @{block.address:#x}:"
        for phi in block.phis:
            incoming = " ".join(
                f"[bb{predecessor}: {format_operand(value)}]" for predecessor, value in phi.incoming
            )
            yield f"    {_defines(phi.output)} = phi {incoming}"
        for operation in block.operations:
            yield f"    {self.operation(operation)}"
        yield f"    {self.terminator(block.terminator, function)}"

    def function(self, function: Function) -> Iterator[str]:
        yield f"function {function.name} @{function.entry:#x}"
        for function_input in function.inputs:
            yield f"  input {function_input.register} -> {_defines(function_input.value)}"
        yield f"  outputs ({', '.join(function.output_registers)})"
        for block in function.blocks:
            yield from self.block(block, function)

    def module_lines(self) -> Iterator[str]:
        module = self.module
        target = module.target
        yield f"module {module.name}"
        yield (
            f"target {target.architecture} {target.endianness}-endian "
            f"pointer={target.pointer_width} sp={target.stack_pointer} "
            f"pc={target.program_counter}"
        )
        yield ""
        for register in module.registers:
            yield f"register {register.name}:{register.width} @{register.offset:#x}"
        yield ""
        for region in module.memory:
            permissions = (
                ("r" if region.readable else "-")
                + ("w" if region.writable else "-")
                + ("x" if region.executable else "-")
            )
            initial = "data" if region.data is not None else "zero"
            yield (
                f"memory {region.name} {region.start:#x} +{region.size:#x} {permissions} {initial}"
            )
        for external in module.externals:
            addresses = ", ".join(f"{address:#x}" for address in external.addresses)
            suffix = " noreturn" if external.no_return else ""
            yield f"extern {external.name} [{addresses}]{suffix}"
        for function in module.functions:
            yield ""
            yield from self.function(function)


def format_module(module: Module) -> str:
    return "\n".join(_Printer(module).module_lines()) + "\n"

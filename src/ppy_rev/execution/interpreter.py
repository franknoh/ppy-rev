"""Concrete RevIR interpreter: the semantic oracle for lifting, simplification, and solving.

Execution is deliberately strict. Anything RevIR cannot faithfully model (unsupported
operations, user ops, unknown call targets, unresolved indirect jumps, mismatched return
addresses, memory faults, division by zero) stops execution with an `ExecutionError`
that says where and why.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from ppy_rev.diagnostics import Location, PpyRevError
from ppy_rev.execution.memory import ConcreteMemory, MemoryFaultError
from ppy_rev.ir import semantics
from ppy_rev.ir.model import (
    BinaryOp,
    Block,
    Branch,
    Call,
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
    UnaryOp,
    Unsupported,
    UserOp,
    mask,
)


class FaultKind(StrEnum):
    UNSUPPORTED = "unsupported"
    MEMORY_FAULT = "memory-fault"
    DIVISION_BY_ZERO = "division-by-zero"
    UNKNOWN_CALL_TARGET = "unknown-call-target"
    UNRESOLVED_INDIRECT_JUMP = "unresolved-indirect-jump"
    RETURN_ADDRESS_MISMATCH = "return-address-mismatch"
    NO_RETURN_RETURNED = "noreturn-returned"
    STEP_LIMIT = "step-limit"
    CALL_DEPTH_LIMIT = "call-depth-limit"


class ExecutionError(PpyRevError):
    def __init__(self, kind: FaultKind, message: str, location: Location) -> None:
        where = location.describe()
        super().__init__(f"{message} ({where})" if where else message)
        self.kind = kind
        self.location = location


class ExternalHandler(Protocol):
    def __call__(
        self, name: str, registers: dict[str, int], memory: ConcreteMemory
    ) -> dict[str, int]:
        """Model the external function `name`.

        `registers` is the state at the call (the return address has been pushed). Return
        the register state the function leaves behind, before its return address is
        popped; the interpreter performs the return itself.
        """
        ...


@dataclass(frozen=True, slots=True)
class Limits:
    max_steps: int = 1_000_000
    max_call_depth: int = 200


type InstructionObserver = Callable[[int], None]
type CallObserver = Callable[[int, dict[str, int]], None]
"""Called with the call instruction's address and the registers passed, before dispatch."""


def no_externals(name: str, registers: dict[str, int], memory: ConcreteMemory) -> dict[str, int]:
    del registers, memory
    raise KeyError(name)


class Interpreter:
    def __init__(
        self,
        module: Module,
        memory: ConcreteMemory,
        externals: ExternalHandler = no_externals,
        limits: Limits | None = None,
        observer: InstructionObserver | None = None,
        call_observer: CallObserver | None = None,
    ) -> None:
        self.module = module
        self.memory = memory
        self.externals = externals
        self.limits = limits or Limits()
        self.observer = observer
        self.call_observer = call_observer
        self.steps = 0
        self._stack_pointer = module.target.stack_pointer
        self._pointer_width = module.target.pointer_width
        self._functions = {function.entry: function for function in module.functions}
        self._externals = {
            address: external.name
            for external in module.externals
            for address in external.addresses
        }

    def call(
        self, function: Function, registers: Mapping[str, int], expected_return: int | None
    ) -> dict[str, int]:
        """Run `function` to its return and yield its output registers.

        `expected_return` is the address the function must return to (what the caller
        pushed), or None to accept any.
        """
        return self._run(function, dict(registers), expected_return, depth=0)

    # -- execution -----------------------------------------------------------------------

    def _run(
        self,
        function: Function,
        registers: dict[str, int],
        expected_return: int | None,
        depth: int,
    ) -> dict[str, int]:
        if depth > self.limits.max_call_depth:
            raise ExecutionError(
                FaultKind.CALL_DEPTH_LIMIT,
                f"call depth exceeds {self.limits.max_call_depth}",
                Location(function=function.name),
            )
        values: dict[int, int] = {}
        for item in function.inputs:
            values[item.value.id] = registers.get(item.register, 0) & mask(item.value.width)
        block = function.blocks[0]
        previous = -1
        while True:
            if block.phis:
                updates = [
                    (phi.output.id, self._value(values, dict(phi.incoming)[previous]))
                    for phi in block.phis
                ]
                for identifier, value in updates:
                    values[identifier] = value
            self._execute_block(function, block, values, depth)
            terminator = block.terminator
            origin = terminator.origin
            match terminator:
                case Jump():
                    previous, block = block.id, function.blocks[terminator.target]
                case Branch():
                    taken = self._value(values, terminator.condition) != 0
                    target = terminator.true_target if taken else terminator.false_target
                    previous, block = block.id, function.blocks[target]
                case IndirectJump():
                    address = self._value(values, terminator.address)
                    target = next(
                        (block_id for known, block_id in terminator.targets if known == address),
                        None,
                    )
                    if target is None:
                        raise self._error(
                            FaultKind.UNRESOLVED_INDIRECT_JUMP,
                            f"indirect jump to {address:#x} is not a recovered target",
                            function,
                            block,
                            origin,
                        )
                    previous, block = block.id, function.blocks[target]
                case Return():
                    if terminator.return_address is not None and expected_return is not None:
                        actual = self._value(values, terminator.return_address)
                        if actual != expected_return:
                            raise self._error(
                                FaultKind.RETURN_ADDRESS_MISMATCH,
                                f"returns to {actual:#x}, expected {expected_return:#x}",
                                function,
                                block,
                                origin,
                            )
                    return {
                        register: self._value(values, value)
                        for register, value in zip(
                            function.output_registers, terminator.values, strict=True
                        )
                    }
                case TailCall():
                    self._call(
                        function,
                        block,
                        terminator.call,
                        values,
                        depth,
                        tail=True,
                        tail_return=expected_return,
                    )
                    return {
                        register: self._value(values, value)
                        for register, value in zip(
                            function.output_registers, terminator.values, strict=True
                        )
                    }
                case Halt():
                    raise self._error(
                        FaultKind.NO_RETURN_RETURNED,
                        "a non-returning call returned",
                        function,
                        block,
                        origin,
                    )
                case Stop():
                    raise self._error(
                        FaultKind.UNSUPPORTED, terminator.reason, function, block, origin
                    )

    def _execute_block(
        self, function: Function, block: Block, values: dict[int, int], depth: int
    ) -> None:
        starts = block.instructions
        next_start = 0
        for position, operation in enumerate(block.operations):
            while next_start < len(starts) and starts[next_start].position <= position:
                self._observe(starts[next_start].address)
                next_start += 1
            self.steps += 1
            if self.steps > self.limits.max_steps:
                raise self._error(
                    FaultKind.STEP_LIMIT,
                    f"executed more than {self.limits.max_steps} operations",
                    function,
                    block,
                    operation.origin,
                )
            try:
                self._execute(function, block, operation, values, depth)
            except MemoryFaultError as fault:
                raise self._error(
                    FaultKind.MEMORY_FAULT, str(fault), function, block, operation.origin
                ) from fault
            except semantics.DivisionByZeroError as fault:
                raise self._error(
                    FaultKind.DIVISION_BY_ZERO, str(fault), function, block, operation.origin
                ) from fault
        for start in starts[next_start:]:
            self._observe(start.address)

    def _observe(self, address: int) -> None:
        if self.observer is not None:
            self.observer(address)

    def _execute(
        self,
        function: Function,
        block: Block,
        operation: Operation,
        values: dict[int, int],
        depth: int,
    ) -> None:
        match operation:
            case BinaryOp(opcode=opcode, output=output, left=left, right=right):
                values[output.id] = semantics.binary(
                    opcode, self._value(values, left), self._value(values, right), left.width
                )
            case UnaryOp(opcode=opcode, output=output, operand=operand):
                values[output.id] = semantics.unary(
                    opcode, self._value(values, operand), operand.width, output.width
                )
            case Subpiece(output=output, operand=operand, low_bit=low_bit):
                values[output.id] = semantics.subpiece(
                    self._value(values, operand), low_bit, output.width
                )
            case Piece(output=output, high=high, low=low):
                values[output.id] = semantics.piece(
                    self._value(values, high), self._value(values, low), low.width
                )
            case Load(output=output, address=address):
                values[output.id] = self.memory.load(self._value(values, address), output.width)
            case Store(address=address, value=value):
                self.memory.store(
                    self._value(values, address), self._value(values, value), value.width
                )
            case Call():
                self._call(function, block, operation, values, depth, tail=False, tail_return=None)
            case UserOp():
                raise self._error(
                    FaultKind.UNSUPPORTED,
                    f"user operation {operation.name} has no modeled semantics",
                    function,
                    block,
                    operation.origin,
                )
            case Unsupported():
                raise self._error(
                    FaultKind.UNSUPPORTED, operation.reason, function, block, operation.origin
                )

    def _call(
        self,
        function: Function,
        block: Block,
        call: Call,
        values: dict[int, int],
        depth: int,
        *,
        tail: bool,
        tail_return: int | None,
    ) -> None:
        arguments = {
            register: self._value(values, value)
            for register, value in zip(call.argument_registers, call.arguments, strict=True)
        }
        target = call.target
        address: int
        match target:
            case DirectTarget():
                address = target.address
            case ExternalTarget():
                address = target.address
            case IndirectTarget():
                address = self._value(values, target.address)
        if self.call_observer is not None:
            self.call_observer(call.origin.address, dict(arguments))
        callee = self._functions.get(address)
        external = self._externals.get(address)
        if callee is not None:
            # A call instruction pushed the return address; a tail jump reuses the caller's.
            expected = tail_return if tail else self._pushed_return_address(arguments)
            outputs = self._run(callee, arguments, expected, depth + 1)
        elif external is not None:
            outputs = self._external(function, block, call, external, arguments)
        else:
            raise self._error(
                FaultKind.UNKNOWN_CALL_TARGET,
                f"call to {address:#x}, which is neither a lifted function nor an import",
                function,
                block,
                call.origin,
            )
        for register, result in zip(call.result_registers, call.results, strict=True):
            value = outputs.get(register, arguments.get(register, 0))
            values[result.id] = value & mask(result.width)

    def _pushed_return_address(self, arguments: Mapping[str, int]) -> int | None:
        stack = arguments.get(self._stack_pointer)
        if stack is None:
            return None
        return self.memory.load(stack, self._pointer_width)

    def _external(
        self,
        function: Function,
        block: Block,
        call: Call,
        name: str,
        arguments: dict[str, int],
    ) -> dict[str, int]:
        try:
            outputs = self.externals(name, dict(arguments), self.memory)
        except KeyError:
            raise self._error(
                FaultKind.UNSUPPORTED,
                f"no model for imported function {name}",
                function,
                block,
                call.origin,
            ) from None
        except MemoryFaultError as fault:
            raise self._error(
                FaultKind.MEMORY_FAULT, f"{name}: {fault}", function, block, call.origin
            ) from fault
        stack = outputs.get(self._stack_pointer, arguments.get(self._stack_pointer))
        if stack is not None:
            # The import returns like any function, popping the return address on top of
            # the stack: the one this call pushed, or the caller's for a tail jump.
            outputs[self._stack_pointer] = (stack + self._pointer_width // 8) & mask(
                self._pointer_width
            )
        return outputs

    @staticmethod
    def _value(values: dict[int, int], operand: Operand) -> int:
        if isinstance(operand, Const):
            return operand.value
        return values[operand.id]

    @staticmethod
    def _error(
        kind: FaultKind, message: str, function: Function, block: Block, origin: Origin
    ) -> ExecutionError:
        return ExecutionError(
            kind,
            message,
            Location(function=function.name, block=block.id, address=origin.address),
        )

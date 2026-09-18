"""Backward slicing: operations that cannot influence whether the goal is reached.

Success is decided by control flow (branch conditions, jump targets, return addresses),
by memory (anything stored may be read by something that matters), by faults (loads and
divisions), and by the goal and avoid calls themselves. Everything those depend on is
relevant. What is left is output: messages printed by library calls or by helper
functions that only print, and the computations feeding them. Such work is skipped during
symbolic execution.

The slice is conservative. A call is skipped only when its callee is a known output-only
library function, or a lifted function that provably does nothing observable but output
(it writes only its own stack frame and calls only functions of the same kind), when none
of its results except the stack pointer are used, and when neither it nor anything it
calls is a goal or avoid instruction. Such a function may read the caller's data — that is
what printing it looks like — and may loop, in which case skipping it assumes the loop
ends; a solution that depended on it not ending would fail the concrete re-run.
"""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.abi import calling_convention
from ppy_rev.analysis.locations import Locations
from ppy_rev.analysis.program import calls, external_name
from ppy_rev.ir.cfg import control_flow
from ppy_rev.ir.model import (
    DIVISION_OPCODES,
    BinaryOp,
    Branch,
    Call,
    Const,
    DirectTarget,
    Function,
    IndirectJump,
    IndirectTarget,
    Load,
    Module,
    Operand,
    Operation,
    Phi,
    Piece,
    Return,
    Store,
    Subpiece,
    TailCall,
    UnaryOp,
    operation_inputs,
    operation_output,
)

OUTPUT_FUNCTIONS = frozenset(
    {"puts", "putchar", "printf", "__printf_chk", "fputs", "fflush", "setbuf", "setvbuf"}
)
"""Library functions whose only effect is output (formats that write memory are refused)."""
_FRAME_EXTENT = 1 << 16
_CYCLE = -(1 << 62)
"""Marks an address that only leads back to the phi being resolved, so it adds nothing."""


type OperationKey = tuple[int, int, int]
"""(function entry, block id, operation index)."""


@dataclass(frozen=True, slots=True)
class Slice:
    skipped: frozenset[OperationKey]
    """Operations whose effects cannot matter: pure computations and output-only calls."""
    output_functions: frozenset[int]
    """Lifted functions that only produce output."""
    looping_output: frozenset[int] = frozenset()
    """Those of them that contain a loop, so skipping them assumes the loop ends."""

    def skips(self, entry: int, block: int, index: int) -> bool:
        return (entry, block, index) in self.skipped


def backward_slice(
    module: Module, protected: frozenset[int], outermost: int | None = None
) -> Slice:
    """The slice for goals and avoids at the instruction addresses in `protected`.

    The values the `outermost` function (main) returns are not used by anything that
    decides reaching a goal inside the program.
    """
    stack_pointer = calling_convention(module.target).stack_pointer
    output_functions = _output_functions(module, protected, stack_pointer)
    skipped: set[OperationKey] = set()
    for function in module.functions:
        skipped |= _FunctionSlice(
            module,
            function,
            protected,
            output_functions,
            stack_pointer,
            returns_matter=function.entry != outermost,
        ).skipped()
    looping = {
        entry
        for entry in output_functions
        if (item := module.function_at(entry)) is not None and loops(item)
    }
    return Slice(frozenset(skipped), frozenset(output_functions), frozenset(looping))


def _output_functions(module: Module, protected: frozenset[int], stack_pointer: str) -> set[int]:
    """Lifted functions that do nothing observable except output, to a fixpoint."""
    candidates = {
        function.entry
        for function in module.functions
        if _local_only(module, function, protected, stack_pointer)
    }
    changed = True
    while changed:
        changed = False
        for entry in sorted(candidates):
            function = module.function_at(entry)
            if function is None:
                continue
            for call, _ in calls(function):
                if not _output_call(module, call, candidates, protected):
                    candidates.discard(entry)
                    changed = True
                    break
    return candidates


def loops(function: Function) -> bool:
    """Whether control flow ever returns to a block that dominates it."""
    flow = control_flow(function)
    return any(
        flow.dominates(target, source)
        for source, targets in enumerate(flow.successors)
        for target in targets
    )


def _local_only(
    module: Module, function: Function, protected: frozenset[int], stack_pointer: str
) -> bool:
    locations = Locations(function)
    frame = next(
        (item.value.id for item in function.inputs if item.register == stack_pointer), None
    )
    width = module.target.pointer_width
    # A call returns with the stack pointer just above the return address it pushed, and
    # with the registers it may not clobber — the frame pointer among them — as it got them.
    convention = calling_convention(module.target)
    popped: dict[int, Operand] = {}
    preserved: dict[int, Operand] = {}
    for call, _ in calls(function):
        arguments = dict(zip(call.argument_registers, call.arguments, strict=True))
        for register, result in zip(call.result_registers, call.results, strict=True):
            if register not in arguments:
                continue
            if register == stack_pointer:
                popped[result.id] = arguments[register]
            elif register not in convention.clobbers:
                preserved[result.id] = arguments[register]

    def signed(total: int) -> int:
        wrapped = total & ((1 << width) - 1)
        return wrapped - (1 << width) if wrapped >> (width - 1) else wrapped

    def frame_offset(address: Operand, resolving: frozenset[int] = frozenset()) -> int | None:
        """How far below the function's own frame `address` points, if it does at all."""
        base, offset = locations.of(address)
        adjustment = 0
        while base[0] == "value" and (base[1] in popped or base[1] in preserved):
            identifier = int(base[1])
            through = popped.get(identifier)
            step = width // 8 if through is not None else 0
            outer_base, outer_offset = locations.of(through or preserved[identifier])
            base, adjustment = outer_base, adjustment + outer_offset + step
        if frame is not None and base == ("value", frame):
            return signed(offset + adjustment)
        identifier = base[1]
        if base[0] != "value" or not isinstance(identifier, int):
            return None
        if identifier in resolving:
            return _CYCLE  # a loop carrying the stack pointer back to a phi it came from
        definition = locations.definitions.get(identifier)
        if not isinstance(definition, Phi):
            return None
        # A loop header merges the stack pointer from the entry and from a balanced body,
        # so every incoming edge that says something must say the same thing.
        incoming = {
            frame_offset(value, resolving | {identifier}) for _, value in definition.incoming
        }
        known = incoming - {_CYCLE}
        if len(known) != 1 or (only := known.pop()) is None:
            return None
        return signed(only + offset + adjustment)

    for block in function.blocks:
        if any(start.address in protected for start in block.instructions):
            return False
        if isinstance(block.terminator, IndirectJump | TailCall):
            return False
        for operation in block.operations:
            match operation:
                case Store(address=address):
                    offset = frame_offset(address)
                    if offset is None or not -_FRAME_EXTENT <= offset <= 0:
                        return False
                case Load():
                    pass  # reading is what printing a caller's data looks like
                case BinaryOp(opcode=opcode) if opcode in DIVISION_OPCODES:
                    return False
                case Call() | BinaryOp() | UnaryOp() | Subpiece() | Piece():
                    pass
                case _:
                    return False
    return True


def _output_call(
    module: Module, call: Call, output_functions: set[int], protected: frozenset[int]
) -> bool:
    if call.origin.address in protected:
        return False
    match call.target:
        case DirectTarget(address=address) if address in output_functions:
            return True
        case IndirectTarget():
            return False
        case _:
            return external_name(module, call) in OUTPUT_FUNCTIONS


class _FunctionSlice:
    def __init__(
        self,
        module: Module,
        function: Function,
        protected: frozenset[int],
        output_functions: set[int],
        stack_pointer: str,
        returns_matter: bool,
    ) -> None:
        self.module = module
        self.function = function
        self.returns_matter = returns_matter
        self.protected = protected
        self.output_functions = output_functions
        self.stack_pointer = stack_pointer
        self.definitions: dict[int, Phi | Operation] = {}
        for block in function.blocks:
            for phi in block.phis:
                self.definitions[phi.output.id] = phi
            for operation in block.operations:
                for output in operation_output(operation):
                    self.definitions[output.id] = operation

    def skipped(self) -> set[OperationKey]:
        skippable_calls = {
            (block.id, index)
            for block in self.function.blocks
            for index, operation in enumerate(block.operations)
            if isinstance(operation, Call)
            and _output_call(self.module, operation, self.output_functions, self.protected)
        }
        while True:
            relevant = self._relevant(skippable_calls)
            used = {
                (block.id, index)
                for block in self.function.blocks
                for index, operation in enumerate(block.operations)
                if (block.id, index) in skippable_calls
                and isinstance(operation, Call)
                and any(
                    result.id in relevant
                    for register, result in zip(
                        operation.result_registers, operation.results, strict=True
                    )
                    if register != self.stack_pointer
                )
            }
            if not used:
                break
            skippable_calls -= used
        skipped: set[OperationKey] = set()
        entry = self.function.entry
        for block in self.function.blocks:
            for index, operation in enumerate(block.operations):
                if (block.id, index) in skippable_calls or (
                    isinstance(operation, BinaryOp | UnaryOp | Subpiece | Piece)
                    and not (operation.output.id in relevant or _may_fault(operation))
                ):
                    skipped.add((entry, block.id, index))
        return skipped

    def _relevant(self, skippable_calls: set[tuple[int, int]]) -> set[int]:
        relevant: set[int] = set()
        work: list[Operand] = []
        for block in self.function.blocks:
            # Phis are evaluated whenever their block is entered, so what feeds them stays.
            for phi in block.phis:
                work.extend(value for _, value in phi.incoming)
            for index, operation in enumerate(block.operations):
                match operation:
                    case Call() if (block.id, index) in skippable_calls:
                        # Only the stack pointer comes out of a skipped call.
                        work.extend(
                            argument
                            for register, argument in zip(
                                operation.argument_registers, operation.arguments, strict=True
                            )
                            if register == self.stack_pointer
                        )
                    case BinaryOp() | UnaryOp() | Subpiece() | Piece() if not _may_fault(operation):
                        pass
                    case _:
                        work.extend(operation_inputs(operation))
            match block.terminator:
                case Branch(condition=condition):
                    work.append(condition)
                case IndirectJump(address=address):
                    work.append(address)
                case Return(values=values, return_address=return_address):
                    if self.returns_matter:
                        work.extend(values)
                    if return_address is not None:
                        work.append(return_address)
                case TailCall(call=call, values=values):
                    work.extend(call.arguments)
                    work.extend(values)
                case _:
                    pass
        while work:
            operand = work.pop()
            if isinstance(operand, Const) or operand.id in relevant:
                continue
            relevant.add(operand.id)
            match self.definitions.get(operand.id):
                case Phi(incoming=incoming):
                    work.extend(value for _, value in incoming)
                case BinaryOp() | UnaryOp() | Subpiece() | Piece() as pure:
                    work.extend(operation_inputs(pure))
                case _:
                    pass
        return relevant


def _may_fault(operation: Operation) -> bool:
    return (
        isinstance(operation, BinaryOp)
        and operation.opcode in DIVISION_OPCODES
        and not (isinstance(operation.right, Const) and operation.right.value != 0)
    )

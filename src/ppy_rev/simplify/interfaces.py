"""Interprocedural narrowing of register interfaces.

The lifter passes the complete register state through every call and return. This pass
computes, for every lifted function:

- `writes`: registers whose value on return may differ from their value on entry (a least
  fixpoint, where a callee result for a register the callee never writes is the argument);
- `observed`: registers some caller may read after a return — the calling convention's
  observable set (for callers outside the module) plus what lifted call sites actually use;
- `reads`: registers whose entry value can influence behaviour, given the above.

Calls then pass only what the callee reads, functions return `writes ∩ observed`, and
results of unwritten registers become the value passed in. Operations that may fault
(loads, divisions by a non-constant) and all effects are kept, so behaviour — including
failures — is unchanged.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace

from ppy_rev.abi import calling_convention
from ppy_rev.ir.model import (
    DIVISION_OPCODES,
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
    operation_inputs,
    operation_output,
)
from ppy_rev.ir.transform import (
    Use,
    map_operation,
    map_phi,
    map_terminator,
    renumber,
    resolver,
)

type _Mark = Callable[[Operand], None]
type _MarkCall = Callable[[Call], None]


def trim_interfaces(module: Module) -> Module:
    analysis = _InterfaceAnalysis(module)
    analysis.solve()
    return replace(
        module, functions=tuple(analysis.rewrite(function) for function in module.functions)
    )


@dataclass(slots=True)
class _Liveness:
    live: set[int]
    reads: frozenset[str]
    observations: dict[int, set[str]]
    use: Use


class _InterfaceAnalysis:
    def __init__(self, module: Module) -> None:
        self.convention = calling_convention(module.target)
        self.order = {register.name: index for index, register in enumerate(module.registers)}
        self.every = frozenset(self.order)
        self.functions = {function.entry: function for function in module.functions}
        self.writes: dict[int, frozenset[str]] = dict.fromkeys(self.functions, frozenset())
        self.reads: dict[int, frozenset[str]] = dict.fromkeys(self.functions, frozenset())
        observed = self.convention.observed & self.every
        self.observed: dict[int, set[str]] = {entry: set(observed) for entry in self.functions}

    def ordered(self, registers: Iterable[str]) -> tuple[str, ...]:
        return tuple(sorted(registers, key=self.order.__getitem__))

    # -- callee interfaces ---------------------------------------------------------------

    def _known(self, target: CallTarget) -> int | None:
        if isinstance(target, DirectTarget) and target.address in self.functions:
            return target.address
        return None

    def callee_writes(self, target: CallTarget) -> frozenset[str]:
        if isinstance(target, ExternalTarget):
            return self.convention.clobbers & self.every
        known = self._known(target)
        return self.every if known is None else self.writes[known]

    def callee_reads(self, target: CallTarget) -> frozenset[str]:
        if isinstance(target, ExternalTarget):
            return self.convention.reads & self.every
        known = self._known(target)
        return self.every if known is None else self.reads[known]

    def callee_outputs(self, target: CallTarget) -> frozenset[str]:
        if isinstance(target, ExternalTarget):
            return self.convention.clobbers & self.every
        known = self._known(target)
        if known is None:
            return self.every
        return self.writes[known] & frozenset(self.observed[known])

    def outputs(self, entry: int) -> frozenset[str]:
        return self.writes[entry] & frozenset(self.observed[entry])

    # -- per-function analyses -----------------------------------------------------------

    def pass_through(self, function: Function) -> Use:
        replacements: dict[int, Operand] = {}
        for call in _calls(function):
            written = self.callee_writes(call.target)
            arguments = dict(zip(call.argument_registers, call.arguments, strict=True))
            for register, result in zip(call.result_registers, call.results, strict=True):
                if register not in written and register in arguments:
                    replacements[result.id] = arguments[register]
        use = resolver(replacements)
        changed = True
        while changed:
            changed = False
            for block in function.blocks:
                for phi in block.phis:
                    if phi.output.id in replacements:
                        continue
                    distinct = {use(value) for _, value in phi.incoming} - {phi.output}
                    if len(distinct) == 1:
                        replacements[phi.output.id] = distinct.pop()
                        changed = True
        return use

    def compute_writes(self, function: Function) -> frozenset[str]:
        use = self.pass_through(function)
        entry_values = {item.register: item.value for item in function.inputs}
        written: set[str] = set()
        for block in function.blocks:
            terminator = block.terminator
            if isinstance(terminator, Return | TailCall):
                for register, value in zip(
                    function.output_registers, terminator.values, strict=True
                ):
                    if use(value) != entry_values.get(register):
                        written.add(register)
        return frozenset(written)

    def liveness(self, function: Function, outputs: frozenset[str]) -> _Liveness:
        use = self.pass_through(function)
        definitions: dict[int, Phi | Operation] = {}
        for block in function.blocks:
            for phi in block.phis:
                definitions[phi.output.id] = phi
            for operation in block.operations:
                for output in operation_output(operation):
                    definitions[output.id] = operation
        live: set[int] = set()
        work: list[Var] = []

        def mark(operand: Operand) -> None:
            resolved = use(operand)
            if isinstance(resolved, Var) and resolved.id not in live:
                live.add(resolved.id)
                work.append(resolved)

        def mark_call(call: Call) -> None:
            if isinstance(call.target, IndirectTarget):
                mark(call.target.address)
            reads = self.callee_reads(call.target)
            for register, argument in zip(call.argument_registers, call.arguments, strict=True):
                if register in reads:
                    mark(argument)

        for block in function.blocks:
            for operation in block.operations:
                match operation:
                    case Call():
                        mark_call(operation)
                    case BinaryOp() if _may_fault(operation):
                        mark(operation.left)
                        mark(operation.right)
                    case Load() | Store() | UserOp() | Unsupported():
                        for operand in operation_inputs(operation):
                            mark(operand)
                    case _:
                        pass
            self._mark_terminator(function, block.terminator, outputs, mark, mark_call)
        while work:
            var = work.pop()
            definition = definitions.get(var.id)
            match definition:
                case Phi():
                    for _, value in definition.incoming:
                        mark(value)
                case BinaryOp() | UnaryOp() | Subpiece() | Piece():
                    for operand in operation_inputs(definition):
                        mark(operand)
                case _:
                    pass
        observations: dict[int, set[str]] = {}
        for call in _calls(function):
            known = self._known(call.target)
            if known is None:
                continue
            for register, result in zip(call.result_registers, call.results, strict=True):
                if result.id in live:
                    observations.setdefault(known, set()).add(register)
        reads = frozenset(item.register for item in function.inputs if item.value.id in live)
        return _Liveness(live, reads, observations, use)

    @staticmethod
    def _mark_terminator(
        function: Function,
        terminator: Terminator,
        outputs: frozenset[str],
        mark: _Mark,
        mark_call: _MarkCall,
    ) -> None:
        match terminator:
            case Return():
                for register, value in zip(
                    function.output_registers, terminator.values, strict=True
                ):
                    if register in outputs:
                        mark(value)
                if terminator.return_address is not None:
                    mark(terminator.return_address)
            case TailCall():
                mark_call(terminator.call)
                for register, value in zip(
                    function.output_registers, terminator.values, strict=True
                ):
                    if register in outputs:
                        mark(value)
            case IndirectJump():
                mark(terminator.address)
            case Branch():
                mark(terminator.condition)
            case Jump() | Halt() | Stop():
                pass

    def solve(self) -> None:
        changed = True
        while changed:
            changed = False
            for entry, function in self.functions.items():
                writes = self.compute_writes(function)
                if writes != self.writes[entry]:
                    self.writes[entry] = writes
                    changed = True
        changed = True
        while changed:
            changed = False
            for entry, function in self.functions.items():
                liveness = self.liveness(function, self.outputs(entry))
                if liveness.reads != self.reads[entry]:
                    self.reads[entry] = liveness.reads
                    changed = True
                for callee, registers in liveness.observations.items():
                    if not registers <= self.observed[callee]:
                        self.observed[callee] |= registers
                        changed = True

    # -- rewriting -----------------------------------------------------------------------

    def rewrite(self, function: Function) -> Function:
        outputs = self.outputs(function.entry)
        liveness = self.liveness(function, outputs)
        use = liveness.use
        blocks: list[Block] = []
        for block in function.blocks:
            phis = tuple(map_phi(phi, use) for phi in block.phis if phi.output.id in liveness.live)
            operations: list[Operation] = []
            positions: list[int] = []
            for operation in block.operations:
                positions.append(len(operations))
                kept = self._rewrite_operation(operation, liveness)
                if kept is not None:
                    operations.append(kept)
            instructions = tuple(
                replace(
                    start,
                    position=positions[start.position]
                    if start.position < len(positions)
                    else len(operations),
                )
                for start in block.instructions
            )
            blocks.append(
                replace(
                    block,
                    phis=phis,
                    operations=tuple(operations),
                    terminator=self._rewrite_terminator(function, block.terminator, use, outputs),
                    instructions=instructions,
                )
            )
        ordered_outputs = self.ordered(outputs)
        return renumber(
            replace(
                function,
                inputs=tuple(item for item in function.inputs if item.register in liveness.reads),
                output_registers=ordered_outputs,
                blocks=tuple(blocks),
            )
        )

    def _rewrite_operation(self, operation: Operation, liveness: _Liveness) -> Operation | None:
        use = liveness.use
        match operation:
            case Call():
                return self._rewrite_call(operation, use)
            case BinaryOp() if _may_fault(operation):
                return map_operation(operation, use)
            case BinaryOp() | UnaryOp() | Subpiece() | Piece():
                if operation.output.id not in liveness.live:
                    return None
                return map_operation(operation, use)
            case Load() | Store() | UserOp() | Unsupported():
                return map_operation(operation, use)

    def _rewrite_call(self, call: Call, use: Use) -> Call:
        reads = self.callee_reads(call.target)
        outputs = self.callee_outputs(call.target)
        arguments = dict(zip(call.argument_registers, call.arguments, strict=True))
        missing = reads - arguments.keys()
        if missing:
            raise ValueError(f"call at {call.origin.address:#x} does not pass {sorted(missing)}")
        results = dict(zip(call.result_registers, call.results, strict=True))
        argument_registers = self.ordered(reads)
        result_registers = self.ordered(outputs & results.keys())
        target = call.target
        if isinstance(target, IndirectTarget):
            target = IndirectTarget(use(target.address), target.candidates)
        return Call(
            target,
            argument_registers,
            tuple(use(arguments[register]) for register in argument_registers),
            result_registers,
            tuple(results[register] for register in result_registers),
            call.origin,
        )

    def _rewrite_terminator(
        self, function: Function, terminator: Terminator, use: Use, outputs: frozenset[str]
    ) -> Terminator:
        values = dict(zip(function.output_registers, _values(terminator), strict=False))
        ordered = self.ordered(outputs)
        match terminator:
            case Return():
                return Return(
                    tuple(use(values[register]) for register in ordered),
                    None if terminator.return_address is None else use(terminator.return_address),
                    terminator.origin,
                )
            case TailCall():
                return TailCall(
                    self._rewrite_call(terminator.call, use),
                    tuple(use(values[register]) for register in ordered),
                    terminator.origin,
                )
            case _:
                return map_terminator(terminator, use)


def _values(terminator: Terminator) -> tuple[Operand, ...]:
    if isinstance(terminator, Return | TailCall):
        return terminator.values
    return ()


def _calls(function: Function) -> list[Call]:
    calls = [
        operation
        for block in function.blocks
        for operation in block.operations
        if isinstance(operation, Call)
    ]
    calls.extend(
        block.terminator.call for block in function.blocks if isinstance(block.terminator, TailCall)
    )
    return calls


def _may_fault(operation: BinaryOp) -> bool:
    if operation.opcode not in DIVISION_OPCODES:
        return False
    return not (isinstance(operation.right, Const) and operation.right.value != 0)

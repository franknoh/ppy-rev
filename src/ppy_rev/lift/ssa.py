"""Raw p-code → RevIR SSA for one function.

SSA construction follows Braun et al., "Simple and Efficient Construction of Static Single
Assignment Form" (CC 2013): variables are read on demand, phis are created lazily, and
trivial phis are removed as soon as they are complete. Construction uses mutable scaffolding
that is frozen into immutable RevIR at the end, with value ids renumbered densely in a
deterministic order.

Every register the function could observe is passed explicitly: calls take and return the
complete register state and returns yield it. `ppy_rev.simplify.interfaces` narrows that to
what is actually used.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ppy_rev.diagnostics import Diagnostic, DiagnosticCode, Location, Severity
from ppy_rev.ghidra.schema import Instruction, PcodeOp, Varnode
from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Block,
    Branch,
    Call,
    CallTarget,
    Const,
    Function,
    FunctionInput,
    Halt,
    IndirectJump,
    IndirectTarget,
    Jump,
    Load,
    Operand,
    Operation,
    Origin,
    Phi,
    Piece,
    Return,
    Stop,
    Store,
    Subpiece,
    TailCall,
    Terminator,
    UnaryOp,
    UnaryOpcode,
    Unsupported,
    UserOp,
    Var,
    mask,
    operation_output,
)
from ppy_rev.lift.cfg import (
    CondGoto,
    FallThrough,
    FunctionCfg,
    Goto,
    HaltExit,
    IndirectGoto,
    PcodeBlock,
    Point,
    ReturnExit,
    StopExit,
    TailCallExit,
)
from ppy_rev.lift.storage import StorageGroup, StoragePartition

BINARY_OPCODES: dict[str, BinaryOpcode] = {
    "INT_ADD": BinaryOpcode.ADD,
    "INT_SUB": BinaryOpcode.SUB,
    "INT_MULT": BinaryOpcode.MUL,
    "INT_DIV": BinaryOpcode.UNSIGNED_DIV,
    "INT_SDIV": BinaryOpcode.SIGNED_DIV,
    "INT_REM": BinaryOpcode.UNSIGNED_REM,
    "INT_SREM": BinaryOpcode.SIGNED_REM,
    "INT_AND": BinaryOpcode.AND,
    "INT_OR": BinaryOpcode.OR,
    "INT_XOR": BinaryOpcode.XOR,
    "INT_LEFT": BinaryOpcode.SHIFT_LEFT,
    "INT_RIGHT": BinaryOpcode.LOGICAL_SHIFT_RIGHT,
    "INT_SRIGHT": BinaryOpcode.ARITHMETIC_SHIFT_RIGHT,
    "INT_EQUAL": BinaryOpcode.EQUAL,
    "INT_NOTEQUAL": BinaryOpcode.NOT_EQUAL,
    "INT_LESS": BinaryOpcode.UNSIGNED_LESS,
    "INT_LESSEQUAL": BinaryOpcode.UNSIGNED_LESS_EQUAL,
    "INT_SLESS": BinaryOpcode.SIGNED_LESS,
    "INT_SLESSEQUAL": BinaryOpcode.SIGNED_LESS_EQUAL,
    "INT_CARRY": BinaryOpcode.UNSIGNED_CARRY,
    "INT_SCARRY": BinaryOpcode.SIGNED_CARRY,
    "INT_SBORROW": BinaryOpcode.SIGNED_BORROW,
    "BOOL_AND": BinaryOpcode.BOOLEAN_AND,
    "BOOL_OR": BinaryOpcode.BOOLEAN_OR,
    "BOOL_XOR": BinaryOpcode.BOOLEAN_XOR,
}

UNARY_OPCODES: dict[str, UnaryOpcode] = {
    "INT_NEGATE": UnaryOpcode.BITWISE_NOT,
    "INT_2COMP": UnaryOpcode.TWOS_COMPLEMENT,
    "BOOL_NEGATE": UnaryOpcode.BOOLEAN_NOT,
    "INT_ZEXT": UnaryOpcode.ZERO_EXTEND,
    "INT_SEXT": UnaryOpcode.SIGN_EXTEND,
    "POPCOUNT": UnaryOpcode.POPCOUNT,
    "LZCOUNT": UnaryOpcode.COUNT_LEADING_ZEROS,
}

FLOAT_PREFIX = "FLOAT_"

type VarKey = tuple[str, int, int]
"""(address space, offset, size in bytes) of a register group or an exact temporary."""


@dataclass(slots=True)
class _Phi:
    id: int
    width: int
    block: int
    key: VarKey
    operands: list[tuple[int, Operand]] = field(default_factory=list[tuple[int, Operand]])
    removed: bool = False


@dataclass(slots=True)
class _Block:
    source: PcodeBlock
    operations: list[Operation] = field(default_factory=list[Operation])
    terminator: Terminator | None = None


@dataclass(frozen=True, slots=True)
class FunctionContext:
    name: str
    registers: StoragePartition
    register_order: tuple[StorageGroup, ...]
    pointer_width: int
    instructions: dict[int, Instruction]
    resolve_call: Callable[[int], CallTarget]


class FunctionBuilder:
    def __init__(self, context: FunctionContext, cfg: FunctionCfg) -> None:
        self.context = context
        self.cfg = cfg
        self.blocks = [_Block(source) for source in cfg.blocks]
        self.diagnostics: list[Diagnostic] = []
        self._next_id = 0
        self._current: dict[VarKey, dict[int, Operand]] = {}
        self._incomplete: dict[int, dict[VarKey, _Phi]] = {}
        self._sealed: set[int] = set()
        self._phis: dict[int, _Phi] = {}
        self._phi_users: dict[int, list[_Phi]] = {}
        self._replacement: dict[int, Operand] = {}
        self._inputs: dict[VarKey, Var] = {}

    # -- values ------------------------------------------------------------------------

    def _new_var(self, width: int) -> Var:
        self._next_id += 1
        return Var(self._next_id, width)

    def _resolve(self, operand: Operand) -> Operand:
        while isinstance(operand, Var) and operand.id in self._replacement:
            operand = self._replacement[operand.id]
        return operand

    @staticmethod
    def _width(key: VarKey) -> int:
        return key[2] * 8

    # -- Braun SSA -----------------------------------------------------------------------

    def write_variable(self, key: VarKey, block: int, value: Operand) -> None:
        self._current.setdefault(key, {})[block] = value

    def read_variable(self, key: VarKey, block: int) -> Operand:
        definitions = self._current.get(key)
        if definitions is not None and block in definitions:
            return self._resolve(definitions[block])
        return self._read_recursive(key, block)

    def _read_recursive(self, key: VarKey, block: int) -> Operand:
        predecessors = self.cfg.blocks[block].predecessors
        value: Operand
        if block not in self._sealed:
            phi = self._new_phi(key, block)
            self._incomplete.setdefault(block, {})[key] = phi
            value = Var(phi.id, phi.width)
        elif not predecessors:
            value = self._entry_value(key)
        elif len(predecessors) == 1:
            value = self.read_variable(key, predecessors[0])
        else:
            phi = self._new_phi(key, block)
            self.write_variable(key, block, Var(phi.id, phi.width))
            value = self._add_phi_operands(phi)
        self.write_variable(key, block, value)
        return value

    def _new_phi(self, key: VarKey, block: int) -> _Phi:
        width = self._width(key)
        self._next_id += 1
        phi = _Phi(id=self._next_id, width=width, block=block, key=key)
        self._phis[phi.id] = phi
        return phi

    def _add_phi_operands(self, phi: _Phi) -> Operand:
        for predecessor in self.cfg.blocks[phi.block].predecessors:
            operand = self.read_variable(phi.key, predecessor)
            phi.operands.append((predecessor, operand))
            if isinstance(operand, Var) and operand.id in self._phis:
                self._phi_users.setdefault(operand.id, []).append(phi)
        return self._try_remove_trivial(phi)

    def _try_remove_trivial(self, phi: _Phi) -> Operand:
        this = Var(phi.id, phi.width)
        same: Operand | None = None
        for _, operand in phi.operands:
            resolved = self._resolve(operand)
            if resolved in (this, same):
                continue
            if same is not None:
                return this
            same = resolved
        if same is None:
            # Every path into this phi runs through itself; the CFG is built from
            # reachable code, so this indicates a lifter bug rather than input data.
            raise AssertionError(f"phi v{phi.id} has no incoming value")
        phi.removed = True
        self._replacement[phi.id] = same
        for user in self._phi_users.get(phi.id, []):
            if not user.removed:
                self._try_remove_trivial(user)
        return same

    def _seal(self, block: int) -> None:
        for phi in self._incomplete.pop(block, {}).values():
            self._add_phi_operands(phi)
        self._sealed.add(block)

    def _entry_value(self, key: VarKey) -> Operand:
        existing = self._inputs.get(key)
        if existing is not None:
            return existing
        value = self._new_var(self._width(key))
        self._inputs[key] = value
        if key[0] != "register":
            self._diagnose(
                DiagnosticCode.MALFORMED_PCODE,
                f"temporary unique:{key[1]:#x}:{key[2]} is read before it is written",
                None,
                None,
            )
        return value

    # -- varnodes ------------------------------------------------------------------------

    def _emit(self, block: int, operation: Operation) -> None:
        self.blocks[block].operations.append(operation)

    def read_varnode(self, block: int, varnode: Varnode, origin: Origin) -> Operand:
        width = varnode.size * 8
        match varnode.space:
            case "const":
                return Const(varnode.offset & mask(width), width)
            case "unique":
                # Temporaries are local to one instruction's p-code and are always read at
                # exactly the size they were written, so each (offset, size) is a variable.
                return self.read_variable(("unique", varnode.offset, varnode.size), block)
            case "register":
                key, group = self._storage(varnode)
                whole = self.read_variable(key, block)
                low_bit = (varnode.offset - group.offset) * 8
                if low_bit == 0 and width == group.size * 8:
                    return whole
                output = self._new_var(width)
                if low_bit == 0:
                    self._emit(block, UnaryOp(UnaryOpcode.TRUNCATE, output, whole, origin))
                else:
                    self._emit(block, Subpiece(output, whole, low_bit, origin))
                return output
            case "ram":
                output = self._new_var(width)
                address = Const(varnode.offset, self.context.pointer_width)
                self._emit(block, Load(output, address, origin))
                return output
            case space:
                output = self._new_var(width)
                self._unsupported_space(block, space, "read", origin, output, ())
                return output

    def write_varnode(self, block: int, varnode: Varnode, value: Operand, origin: Origin) -> None:
        match varnode.space:
            case "unique":
                self.write_variable(("unique", varnode.offset, varnode.size), block, value)
            case "register":
                key, group = self._storage(varnode)
                low_bit = (varnode.offset - group.offset) * 8
                width = varnode.size * 8
                group_width = group.size * 8
                if low_bit == 0 and width == group_width:
                    self.write_variable(key, block, value)
                    return
                old = self.read_variable(key, block)
                combined = value
                if low_bit > 0:
                    low = self._new_var(low_bit)
                    self._emit(block, UnaryOp(UnaryOpcode.TRUNCATE, low, old, origin))
                    joined = self._new_var(width + low_bit)
                    self._emit(block, Piece(joined, combined, low, origin))
                    combined = joined
                high_bits = group_width - low_bit - width
                if high_bits > 0:
                    high = self._new_var(high_bits)
                    self._emit(block, Subpiece(high, old, low_bit + width, origin))
                    joined = self._new_var(group_width)
                    self._emit(block, Piece(joined, high, combined, origin))
                    combined = joined
                self.write_variable(key, block, combined)
            case "ram":
                address = Const(varnode.offset, self.context.pointer_width)
                self._emit(block, Store(address, value, origin))
            case space:
                self._unsupported_space(block, space, "write", origin, None, (value,))

    def _storage(self, varnode: Varnode) -> tuple[VarKey, StorageGroup]:
        group = self.context.registers.group_of(varnode.offset, varnode.size)
        return ("register", group.offset, group.size), group

    def _unsupported_space(
        self,
        block: int,
        space: str,
        action: str,
        origin: Origin,
        output: Var | None,
        inputs: tuple[Operand, ...],
    ) -> None:
        reason = f"{action} of address space {space!r}"
        self._emit(block, Unsupported("VARNODE", output, inputs, reason, origin))
        self._diagnose(DiagnosticCode.UNSUPPORTED_ADDRESS_SPACE, reason, block, origin)

    def _diagnose(
        self,
        code: DiagnosticCode,
        message: str,
        block: int | None,
        origin: Origin | None,
        opcode: str | None = None,
        severity: Severity = Severity.ERROR,
    ) -> None:
        self.diagnostics.append(
            Diagnostic(
                code=code,
                message=message,
                location=Location(
                    function=self.context.name,
                    block=block,
                    address=None if origin is None else origin.address,
                    opcode=opcode,
                ),
                severity=severity,
            )
        )

    # -- operations ----------------------------------------------------------------------

    def _register_keys(self) -> list[VarKey]:
        return [("register", group.offset, group.size) for group in self.context.register_order]

    def _call(self, block: int, target: CallTarget, origin: Origin) -> Call:
        keys = self._register_keys()
        names = tuple(group.name for group in self.context.register_order)
        arguments = tuple(self.read_variable(key, block) for key in keys)
        results = tuple(self._new_var(self._width(key)) for key in keys)
        for key, result in zip(keys, results, strict=True):
            self.write_variable(key, block, result)
        return Call(target, names, arguments, names, results, origin)

    def lift_op(self, block: int, point: Point, op: PcodeOp) -> None:
        origin = Origin(point.address, point.index)
        opcode = op.opcode
        inputs = op.inputs
        if opcode == "COPY":
            self._write_output(block, op, self.read_varnode(block, inputs[0], origin), origin)
        elif opcode in BINARY_OPCODES:
            left = self.read_varnode(block, inputs[0], origin)
            right = self.read_varnode(block, inputs[1], origin)
            output = self._output_var(op)
            self._emit(block, BinaryOp(BINARY_OPCODES[opcode], output, left, right, origin))
            self._write_output(block, op, output, origin)
        elif opcode in UNARY_OPCODES:
            operand = self.read_varnode(block, inputs[0], origin)
            output = self._output_var(op)
            self._emit(block, UnaryOp(UNARY_OPCODES[opcode], output, operand, origin))
            self._write_output(block, op, output, origin)
        elif opcode == "SUBPIECE":
            self._subpiece(block, op, origin)
        elif opcode == "PIECE":
            high = self.read_varnode(block, inputs[0], origin)
            low = self.read_varnode(block, inputs[1], origin)
            output = self._output_var(op)
            self._emit(block, Piece(output, high, low, origin))
            self._write_output(block, op, output, origin)
        elif opcode in ("LOAD", "STORE"):
            self._memory(block, op, origin)
        elif opcode == "CALL":
            target = self.context.resolve_call(inputs[0].offset)
            self._emit(block, self._call(block, target, origin))
        elif opcode == "CALLIND":
            address = self.read_varnode(block, inputs[0], origin)
            flows = self.context.instructions[point.address].flows
            self._emit(block, self._call(block, IndirectTarget(address, flows), origin))
        elif opcode == "CALLOTHER":
            name = op.user_op or f"userop_{inputs[0].offset}"
            operands = tuple(self.read_varnode(block, vn, origin) for vn in inputs[1:])
            output = None if op.output is None else self._output_var(op)
            self._emit(block, UserOp(name, output, operands, origin))
            self._diagnose(
                DiagnosticCode.UNSUPPORTED_USER_OP,
                f"user-defined operation {name!r} has no modeled semantics",
                block,
                origin,
                opcode,
                Severity.WARNING,
            )
            if output is not None:
                self._write_output(block, op, output, origin)
        else:
            self._unsupported(block, op, origin)

    def _output_var(self, op: PcodeOp) -> Var:
        if op.output is None:
            raise AssertionError(f"{op.opcode} without an output")
        return self._new_var(op.output.size * 8)

    def _write_output(self, block: int, op: PcodeOp, value: Operand, origin: Origin) -> None:
        if op.output is None:
            raise AssertionError(f"{op.opcode} without an output")
        self.write_varnode(block, op.output, value, origin)

    def _subpiece(self, block: int, op: PcodeOp, origin: Origin) -> None:
        operand = self.read_varnode(block, op.inputs[0], origin)
        output = self._output_var(op)
        low_bit = op.inputs[1].offset * 8
        if low_bit == 0 and output.width < operand.width:
            self._emit(block, UnaryOp(UnaryOpcode.TRUNCATE, output, operand, origin))
        elif low_bit == 0 and output.width == operand.width:
            self._write_output(block, op, operand, origin)
            return
        else:
            self._emit(block, Subpiece(output, operand, low_bit, origin))
        self._write_output(block, op, output, origin)

    def _memory(self, block: int, op: PcodeOp, origin: Origin) -> None:
        space = op.memory_space
        pointer = op.inputs[1]
        if space != "ram" or pointer.size * 8 != self.context.pointer_width:
            reason = (
                f"{op.opcode} through space {space!r}"
                if space != "ram"
                else f"{op.opcode} with a {pointer.size * 8}-bit pointer"
            )
            output = None if op.output is None else self._output_var(op)
            inputs = tuple(self.read_varnode(block, vn, origin) for vn in op.inputs[1:])
            self._emit(block, Unsupported(op.opcode, output, inputs, reason, origin))
            self._diagnose(DiagnosticCode.UNSUPPORTED_ADDRESS_SPACE, reason, block, origin)
            if output is not None:
                self._write_output(block, op, output, origin)
            return
        address = self.read_varnode(block, pointer, origin)
        if op.opcode == "LOAD":
            output = self._output_var(op)
            self._emit(block, Load(output, address, origin))
            self._write_output(block, op, output, origin)
        else:
            value = self.read_varnode(block, op.inputs[2], origin)
            self._emit(block, Store(address, value, origin))

    def _unsupported(self, block: int, op: PcodeOp, origin: Origin) -> None:
        if op.opcode.startswith(FLOAT_PREFIX):
            code = DiagnosticCode.UNSUPPORTED_FLOAT_OPERATION
            reason = f"floating-point operation {op.opcode}"
        else:
            code = DiagnosticCode.UNSUPPORTED_OPERATION
            reason = f"p-code operation {op.opcode} is not modeled"
        operands = tuple(self.read_varnode(block, vn, origin) for vn in op.inputs)
        output = None if op.output is None else self._output_var(op)
        self._emit(block, Unsupported(op.opcode, output, operands, reason, origin))
        self._diagnose(code, reason, block, origin, op.opcode)
        if output is not None:
            self._write_output(block, op, output, origin)

    # -- blocks --------------------------------------------------------------------------

    def _terminate(self, block_id: int) -> Terminator:
        block = self.blocks[block_id].source
        last = block.ops[-1][0] if block.ops else block.start
        origin = Origin(last.address, max(last.index, 0))
        exit_ = block.exit
        match exit_:
            case FallThrough(target=target) | Goto(target=target):
                return Jump(self.cfg.block_at[target], origin)
            case CondGoto():
                condition = self.read_varnode(block_id, exit_.condition, origin)
                return Branch(
                    condition,
                    self.cfg.block_at[exit_.taken],
                    self.cfg.block_at[exit_.not_taken],
                    origin,
                )
            case IndirectGoto():
                address = self.read_varnode(block_id, exit_.target, origin)
                return IndirectJump(
                    address,
                    tuple((point.address, self.cfg.block_at[point]) for point in exit_.targets),
                    origin,
                )
            case ReturnExit():
                return_address = self.read_varnode(block_id, exit_.target, origin)
                values = tuple(self.read_variable(key, block_id) for key in self._register_keys())
                return Return(values, return_address, origin)
            case TailCallExit(address=address):
                call = self._call(block_id, self.context.resolve_call(address), origin)
                return TailCall(call, call.results, origin)
            case HaltExit():
                return Halt(origin)
            case StopExit(reason=reason):
                self._diagnose(DiagnosticCode.MISSING_INSTRUCTION, reason, block_id, origin)
                return Stop(reason, origin)

    def _fill(self, block_id: int) -> None:
        source = self.blocks[block_id].source
        control_last = isinstance(source.exit, (Goto, CondGoto, IndirectGoto, ReturnExit)) or (
            isinstance(source.exit, TailCallExit) and source.start.index >= 0
        )
        body = source.ops[:-1] if control_last and source.ops else source.ops
        for point, op in body:
            self.lift_op(block_id, point, op)
        self.blocks[block_id].terminator = self._terminate(block_id)

    def build(self) -> Function:
        order = _reverse_postorder(self.cfg)
        filled: set[int] = set()
        for block_id in order:
            if all(p in filled for p in self.cfg.blocks[block_id].predecessors):
                self._seal(block_id)
            self._fill(block_id)
            filled.add(block_id)
            for successor in self.cfg.successors(self.cfg.blocks[block_id]):
                if successor not in self._sealed and all(
                    p in filled for p in self.cfg.blocks[successor].predecessors
                ):
                    self._seal(successor)
        for block_id in order:
            if block_id not in self._sealed:
                self._seal(block_id)
        return self._freeze(order)

    # -- freezing ------------------------------------------------------------------------

    def _freeze(self, order: list[int]) -> Function:
        renumber: dict[int, int] = {}

        def define(var: Var) -> Var:
            renumber[var.id] = len(renumber)
            return Var(renumber[var.id], var.width)

        def use(operand: Operand) -> Operand:
            resolved = self._resolve(operand)
            if isinstance(resolved, Const):
                return resolved
            return Var(renumber[resolved.id], resolved.width)

        names = {
            ("register", group.offset, group.size): (index, group.name)
            for index, group in enumerate(self.context.register_order)
        }

        def input_order(key: VarKey) -> tuple[int, int, int]:
            known = names.get(key)
            return (0, known[0], 0) if known else (1, key[1], key[2])

        inputs = [
            FunctionInput(
                names[key][1] if key in names else f"unique_{key[1]:x}_{key[2]}",
                define(self._inputs[key]),
            )
            for key in sorted(self._inputs, key=input_order)
        ]
        reachable = set(order)
        live_phis: dict[int, list[_Phi]] = {}
        for phi in self._phis.values():
            if not phi.removed and phi.block in reachable:
                live_phis.setdefault(phi.block, []).append(phi)
        # Definitions are numbered before uses are rewritten, block by block in id order.
        for block_id in range(len(self.blocks)):
            for phi in sorted(live_phis.get(block_id, []), key=lambda phi: phi.key):
                define(Var(phi.id, phi.width))
            for operation in self.blocks[block_id].operations:
                for output in operation_output(operation):
                    define(output)
            terminator = self.blocks[block_id].terminator
            if isinstance(terminator, TailCall):
                for result in terminator.call.results:
                    define(result)
        blocks: list[Block] = []
        for block_id, scaffold in enumerate(self.blocks):
            phis = tuple(
                Phi(
                    output=Var(renumber[phi.id], phi.width),
                    incoming=tuple(sorted((pred, use(value)) for pred, value in phi.operands)),
                )
                for phi in sorted(live_phis.get(block_id, []), key=lambda phi: phi.key)
            )
            terminator = scaffold.terminator
            if terminator is None:
                raise AssertionError(f"block {block_id} was never filled")
            blocks.append(
                Block(
                    id=block_id,
                    address=scaffold.source.address,
                    phis=phis,
                    operations=tuple(_rewrite(op, use, renumber) for op in scaffold.operations),
                    terminator=_rewrite_terminator(terminator, use, renumber),
                )
            )
        return Function(
            name=self.context.name,
            entry=self.cfg.entry,
            inputs=tuple(inputs),
            output_registers=tuple(group.name for group in self.context.register_order),
            blocks=tuple(blocks),
        )


def _renamed(var: Var, renumber: dict[int, int]) -> Var:
    return Var(renumber[var.id], var.width)


def _rewrite(
    operation: Operation, use: Callable[[Operand], Operand], renumber: dict[int, int]
) -> Operation:
    match operation:
        case BinaryOp():
            return BinaryOp(
                operation.opcode,
                _renamed(operation.output, renumber),
                use(operation.left),
                use(operation.right),
                operation.origin,
            )
        case UnaryOp():
            return UnaryOp(
                operation.opcode,
                _renamed(operation.output, renumber),
                use(operation.operand),
                operation.origin,
            )
        case Subpiece():
            return Subpiece(
                _renamed(operation.output, renumber),
                use(operation.operand),
                operation.low_bit,
                operation.origin,
            )
        case Piece():
            return Piece(
                _renamed(operation.output, renumber),
                use(operation.high),
                use(operation.low),
                operation.origin,
            )
        case Load():
            return Load(
                _renamed(operation.output, renumber), use(operation.address), operation.origin
            )
        case Store():
            return Store(use(operation.address), use(operation.value), operation.origin)
        case Call():
            return _rewrite_call(operation, use, renumber)
        case UserOp():
            return UserOp(
                operation.name,
                None if operation.output is None else _renamed(operation.output, renumber),
                tuple(use(operand) for operand in operation.inputs),
                operation.origin,
            )
        case Unsupported():
            return Unsupported(
                operation.pcode_opcode,
                None if operation.output is None else _renamed(operation.output, renumber),
                tuple(use(operand) for operand in operation.inputs),
                operation.reason,
                operation.origin,
            )


def _rewrite_call(call: Call, use: Callable[[Operand], Operand], renumber: dict[int, int]) -> Call:
    target = call.target
    if isinstance(target, IndirectTarget):
        target = IndirectTarget(use(target.address), target.candidates)
    return Call(
        target,
        call.argument_registers,
        tuple(use(argument) for argument in call.arguments),
        call.result_registers,
        tuple(_renamed(result, renumber) for result in call.results),
        call.origin,
    )


def _rewrite_terminator(
    terminator: Terminator, use: Callable[[Operand], Operand], renumber: dict[int, int]
) -> Terminator:
    match terminator:
        case Branch():
            return Branch(
                use(terminator.condition),
                terminator.true_target,
                terminator.false_target,
                terminator.origin,
            )
        case IndirectJump():
            return IndirectJump(use(terminator.address), terminator.targets, terminator.origin)
        case Return():
            return Return(
                tuple(use(value) for value in terminator.values),
                None if terminator.return_address is None else use(terminator.return_address),
                terminator.origin,
            )
        case TailCall():
            call = _rewrite_call(terminator.call, use, renumber)
            return TailCall(call, call.results, terminator.origin)
        case Jump() | Halt() | Stop():
            return terminator


def _reverse_postorder(cfg: FunctionCfg) -> list[int]:
    visited: set[int] = set()
    postorder: list[int] = []
    stack: list[tuple[int, int]] = [(0, 0)]
    visited.add(0)
    while stack:
        block_id, next_index = stack.pop()
        successors = cfg.successors(cfg.blocks[block_id])
        if next_index < len(successors):
            stack.append((block_id, next_index + 1))
            successor = successors[next_index]
            if successor not in visited:
                visited.add(successor)
                stack.append((successor, 0))
        else:
            postorder.append(block_id)
    return list(reversed(postorder))

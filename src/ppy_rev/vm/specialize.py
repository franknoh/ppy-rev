"""Specializing a bytecode interpreter to its bytecode, by partial evaluation of RevIR.

Given the interpreter function, its dispatch loop, where its program counter lives, and
what is known when it is entered (register values and memory, from a snapshot taken at the
call), the interpreter is evaluated with everything known folded away. The program counter
is always known, so each trip around the dispatch loop specializes one bytecode
instruction; what depends on unknown data (VM registers holding input, say) remains as
residual RevIR. The result is a function with a block per bytecode instruction reached:
the bytecode translated into RevIR.

Knowledge is used soundly:

- a fact taken from the snapshot (a register value, a memory cell) is checked by a guard at
  the start of the residual function, which stops rather than computing something wrong
  when the interpreter is entered in another state;
- at the loop header only knowledge that no loop iteration can change survives, with the
  program counter and the loop values that follow from it; everything else becomes a
  residual phi. An assumption found wrong restarts the specialization with less knowledge.

Memory is addressed absolutely: pointers into the interpreter's state come from guarded
facts, so the residual code may rely on their values.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ppy_rev.analysis.locations import Location
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.ir import semantics
from ppy_rev.ir.cfg import control_flow
from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Block,
    Branch,
    Call,
    Const,
    Function,
    FunctionInput,
    Halt,
    IndirectJump,
    IndirectTarget,
    Jump,
    Load,
    Module,
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
    Unsupported,
    UserOp,
    Var,
    mask,
    operation_output,
)

MAX_ITERATIONS = 4096
MAX_KEYS_PER_COUNTER = 2
MAX_ATTEMPTS = 24
MAX_BLOCK_VISITS = 256
_MAX_INSTRUCTION_BYTES = 16


class SpecializationError(PpyRevError):
    pass


@dataclass(frozen=True, slots=True)
class EntryState:
    """What holds when the interpreter is entered."""

    registers: Callable[[str], int | None]
    """An input register's value, if it is known."""
    memory: Callable[[int, int], int | None]
    """The `width`-bit little-endian value at an address, if it is known."""


@dataclass(frozen=True, slots=True)
class MemoryCounter:
    location: Location
    """Where the program counter is stored, in terms of the interpreter's own values."""
    width: int


@dataclass(frozen=True, slots=True)
class PhiCounter:
    phi: int
    """The loop-header phi holding the program counter."""


type ProgramCounter = MemoryCounter | PhiCounter


@dataclass(frozen=True, slots=True)
class Interpreter:
    function: Function
    loop_header: int
    """Block id of the dispatch loop header."""
    counter: ProgramCounter
    fetches: frozenset[int]
    """Instruction addresses of the opcode fetch."""
    handlers: frozenset[int]
    """Block ids where handlers start."""


@dataclass(frozen=True, slots=True)
class Iteration:
    """One bytecode instruction: a trip around the dispatch loop at a program counter."""

    counter: int
    block: int
    """The residual block where the instruction starts."""
    blocks: tuple[int, ...]
    opcode: int | None
    handler: int | None
    """Address of the interpreter's handler block that ran."""
    bytecode: tuple[int, ...]
    """Addresses read from read-only memory, in order: the instruction's bytes."""
    successors: tuple[int, ...]
    """Program counters that may run next."""
    exits: tuple[str, ...]
    """How the interpreter may be left from here."""


@dataclass(frozen=True, slots=True)
class Guard:
    register: str | None
    address: int | None
    width: int
    value: int

    def describe(self) -> str:
        subject = self.register if self.register is not None else f"[{self.address:#x}]"
        return f"{subject}:{self.width} == {self.value:#x}"


@dataclass(frozen=True, slots=True)
class Specialization:
    function: Function
    iterations: tuple[Iteration, ...]
    guards: tuple[Guard, ...]
    attempts: int
    bytecode_base: int | None
    """Where program counter zero's opcode is fetched from, when that is consistent."""


def specialize(module: Module, interpreter: Interpreter, entry: EntryState) -> Specialization:
    assumptions = _Assumptions()
    for attempt in range(1, MAX_ATTEMPTS + 1):
        outcome = _Attempt(module, interpreter, entry, assumptions).run()
        if outcome is None:
            continue
        function, iterations, guards, base = outcome
        return Specialization(function, iterations, guards, attempt, base)
    raise SpecializationError(
        f"specializing {interpreter.function.name} did not settle after {MAX_ATTEMPTS} attempts"
    )


# -- abstract values -----------------------------------------------------------------------


type _Fact = tuple[str | None, int | None, int]
"""A guardable fact: (register, address, width)."""


@dataclass(frozen=True, slots=True)
class _Known:
    value: int
    width: int
    facts: frozenset[_Fact] = frozenset()
    """The snapshot facts this value follows from."""


@dataclass(frozen=True, slots=True)
class _Residual:
    var: Var


type _Value = _Known | _Residual


def _facts(*values: _Value) -> frozenset[_Fact]:
    found: frozenset[_Fact] = frozenset()
    for value in values:
        if isinstance(value, _Known):
            found |= value.facts
    return found


@dataclass(slots=True)
class _Assumptions:
    """Knowledge withdrawn by earlier attempts."""

    general_phis: set[int] = field(default_factory=set[int])
    """Loop-header phis that do not follow from the program counter."""
    varying_cells: set[int] = field(default_factory=set[int])
    """Bytes some loop iteration writes."""
    iterations_clobber: bool = False
    """Some iteration writes through an unknown pointer or calls out."""
    general_cells: set[int] = field(default_factory=set[int])
    """Memory cells (by start address) whose known values are not part of the loop key."""


@dataclass(slots=True)
class _Memory:
    facts: dict[int, tuple[int, _Value]] = field(default_factory=dict[int, tuple[int, _Value]])
    """Values stored on this path, by start address, with their width."""
    written: set[int] = field(default_factory=set[int])
    """Bytes written on this path: the snapshot no longer describes them."""
    clobbered: bool = False
    """Something wrote through an unknown pointer: nothing writable is known."""
    carried: set[int] = field(default_factory=set[int])
    """Bytes whose facts were carried into this loop iteration from an earlier one."""

    def copy(self) -> _Memory:
        return _Memory(dict(self.facts), set(self.written), self.clobbered, set(self.carried))

    def store(self, address: int, width: int, value: _Value) -> None:
        size = width // 8
        for start, (fact_width, _) in list(self.facts.items()):
            if start < address + size and address < start + fact_width // 8:
                del self.facts[start]
        self.written.update(range(address, address + size))
        self.carried.difference_update(range(address, address + size))
        self.facts[address] = (width, value)

    def clobber(self) -> None:
        self.facts.clear()
        self.clobbered = True


@dataclass(slots=True)
class _State:
    env: dict[int, _Value]
    memory: _Memory
    visits: dict[int, int] = field(default_factory=dict[int, int])

    def copy(self) -> _State:
        return _State(dict(self.env), self.memory.copy(), dict(self.visits))


@dataclass(slots=True)
class _ResidualBlock:
    address: int
    phis: list[tuple[Var, list[tuple[int, Operand]]]] = field(
        default_factory=list[tuple[Var, list[tuple[int, Operand]]]]
    )
    operations: list[Operation] = field(default_factory=list[Operation])
    terminator: Terminator | None = None


@dataclass(slots=True)
class _Record:
    counter: int
    block: int
    blocks: list[int] = field(default_factory=list[int])
    handler: int | None = None
    bytecode: list[int] = field(default_factory=list[int])
    successors: list[int] = field(default_factory=list[int])
    exits: list[str] = field(default_factory=list[str])


@dataclass(slots=True)
class _Walk:
    state: _State
    block: int
    predecessor: int | None
    residual: int
    record: _Record | None


type _LoopKey = tuple[tuple[int, ...], tuple[tuple[int, int, int], ...]]
"""Known loop-header phi values, and known memory cells as (address, width, value)."""


class _RestartError(Exception):
    """An assumption was withdrawn; start over."""


# -- one attempt ---------------------------------------------------------------------------


class _Attempt:
    def __init__(
        self,
        module: Module,
        interpreter: Interpreter,
        entry: EntryState,
        assumptions: _Assumptions,
    ) -> None:
        self.module = module
        self.interpreter = interpreter
        self.function = interpreter.function
        self.entry = entry
        self.assumptions = assumptions
        flow = control_flow(self.function)
        self.defined_in: dict[int, int] = {}
        for block in self.function.blocks:
            for phi in block.phis:
                self.defined_in[phi.output.id] = block.id
            for operation in block.operations:
                for output in operation_output(operation):
                    self.defined_in[output.id] = block.id
        header = interpreter.loop_header
        self.loop_body = {header}
        work = [
            source
            for source, targets in enumerate(flow.successors)
            if header in targets and flow.dominates(header, source)
        ]
        while work:
            block_id = work.pop()
            if block_id not in self.loop_body:
                self.loop_body.add(block_id)
                work.extend(flow.predecessors[block_id])
        self.header = self.function.blocks[header]
        self.next_var = 0
        self.blocks: list[_ResidualBlock] = []
        self.inputs: dict[int, Var] = {}
        self.facts: dict[_Fact, int] = {}
        """Every snapshot fact read; `guards` holds those that mattered."""
        self.guards: dict[_Fact, int] = {}
        self.specialized: dict[
            tuple[int, tuple[int, ...], tuple[tuple[int, int, int], ...]], int
        ] = {}
        self.keys: dict[int, set[_LoopKey]] = {}
        self.records: list[_Record] = []
        self.iteration_reads: set[int] = set()
        self.fetched: dict[int, int] = {}
        """Opcodes fetched, by address."""
        self.iteration_writes: set[int] = set()
        self.iteration_clobbers = False

    def run(
        self,
    ) -> tuple[Function, tuple[Iteration, ...], tuple[Guard, ...], int | None] | None:
        env: dict[int, _Value] = {}
        for item in self.function.inputs:
            residual = self._var(item.value.width)
            self.inputs[item.value.id] = residual
            known = self.entry.registers(item.register)
            if known is None:
                env[item.value.id] = _Residual(residual)
            else:
                fact: _Fact = (item.register, None, item.value.width)
                self.facts[fact] = known & mask(item.value.width)
                env[item.value.id] = _Known(
                    known & mask(item.value.width), item.value.width, frozenset({fact})
                )
        start = self._new_block(self.function.blocks[0].address)
        work = [_Walk(_State(env, _Memory()), 0, None, start, None)]
        try:
            while work:
                work.extend(self._walk(work.pop()))
                if len(self.records) > MAX_ITERATIONS:
                    raise SpecializationError(
                        f"more than {MAX_ITERATIONS} bytecode instructions were specialized"
                    )
        except _RestartError:
            return None
        if self._withdraw_invariants():
            return None
        return self._freeze()

    def _withdraw_invariants(self) -> bool:
        assumptions = self.assumptions
        if self.iteration_clobbers and not assumptions.iterations_clobber:
            assumptions.iterations_clobber = True
            return True
        conflicts = (self.iteration_writes & self.iteration_reads) - assumptions.varying_cells
        if conflicts:
            assumptions.varying_cells |= conflicts
            return True
        return False

    # -- building ----------------------------------------------------------------------------

    def _var(self, width: int) -> Var:
        self.next_var += 1
        return Var(self.next_var, width)

    def _new_block(self, address: int) -> int:
        self.blocks.append(_ResidualBlock(address))
        return len(self.blocks) - 1

    def _use(self, value: _Value) -> None:
        """`value` now affects the residual program: the facts behind it are guarded."""
        if isinstance(value, _Known):
            for fact in value.facts:
                self.guards[fact] = self.facts[fact]

    def _operand(self, value: _Value) -> Operand:
        match value:
            case _Known():
                self._use(value)
                return Const(value.value, value.width)
            case _Residual():
                return value.var

    def _value(self, env: dict[int, _Value], operand: Operand) -> _Value:
        if isinstance(operand, Const):
            return _Known(operand.value, operand.width)
        found = env.get(operand.id)
        if found is None:
            raise SpecializationError(f"v{operand.id} is used where its definition did not run")
        return found

    # -- walking -----------------------------------------------------------------------------

    def _walk(self, walk: _Walk) -> list[_Walk]:
        """Run native blocks until the path forks, ends, or comes back to the loop header."""
        state, native, predecessor, rblock, record = (
            walk.state,
            walk.block,
            walk.predecessor,
            walk.residual,
            walk.record,
        )
        while True:
            if record is not None and rblock not in record.blocks:
                record.blocks.append(rblock)
            state.visits[native] = state.visits.get(native, 0) + 1
            block = self.function.blocks[native]
            if state.visits[native] > MAX_BLOCK_VISITS:
                raise SpecializationError(
                    f"the block at {block.address:#x} repeats without reaching the dispatch loop"
                )
            if (
                record is not None
                and record.handler is None
                and native in self.interpreter.handlers
            ):
                record.handler = block.address
            if predecessor is not None and block.phis:
                updates = [
                    (phi.output.id, self._value(state.env, dict(phi.incoming)[predecessor]))
                    for phi in block.phis
                ]
                state.env.update(updates)
            for operation in block.operations:
                self._operation(state, operation, rblock, record)
            step = self._terminator(state, block, rblock, record)
            if isinstance(step, list):
                return step
            if step == self.interpreter.loop_header:
                return self._arrive(state, native, rblock, record)
            predecessor, native = native, step

    def _operation(
        self, state: _State, operation: Operation, rblock: int, record: _Record | None
    ) -> None:
        env = state.env
        emit = self.blocks[rblock].operations.append
        match operation:
            case BinaryOp(opcode=opcode, output=output, left=left, right=right):
                left_value, right_value = self._value(env, left), self._value(env, right)
                if isinstance(left_value, _Known) and isinstance(right_value, _Known):
                    try:
                        result = semantics.binary(
                            opcode, left_value.value, right_value.value, left.width
                        )
                    except semantics.DivisionByZeroError:
                        pass  # the fault must still happen
                    else:
                        env[output.id] = _Known(
                            result & mask(output.width),
                            output.width,
                            _facts(left_value, right_value),
                        )
                        return
                residual = self._var(output.width)
                emit(
                    BinaryOp(
                        opcode,
                        residual,
                        self._operand(left_value),
                        self._operand(right_value),
                        operation.origin,
                    )
                )
                env[output.id] = _Residual(residual)
            case UnaryOp(opcode=opcode, output=output, operand=inner):
                inner_value = self._value(env, inner)
                if isinstance(inner_value, _Known):
                    result = semantics.unary(opcode, inner_value.value, inner.width, output.width)
                    env[output.id] = _Known(
                        result & mask(output.width), output.width, inner_value.facts
                    )
                    return
                residual = self._var(output.width)
                emit(UnaryOp(opcode, residual, self._operand(inner_value), operation.origin))
                env[output.id] = _Residual(residual)
            case Subpiece(output=output, operand=inner, low_bit=low_bit):
                inner_value = self._value(env, inner)
                if isinstance(inner_value, _Known):
                    result = semantics.subpiece(inner_value.value, low_bit, output.width)
                    env[output.id] = _Known(result, output.width, inner_value.facts)
                    return
                residual = self._var(output.width)
                emit(Subpiece(residual, self._operand(inner_value), low_bit, operation.origin))
                env[output.id] = _Residual(residual)
            case Piece(output=output, high=high, low=low):
                high_value, low_value = self._value(env, high), self._value(env, low)
                if isinstance(high_value, _Known) and isinstance(low_value, _Known):
                    result = semantics.piece(high_value.value, low_value.value, low.width)
                    env[output.id] = _Known(result, output.width, _facts(high_value, low_value))
                    return
                residual = self._var(output.width)
                emit(
                    Piece(
                        residual,
                        self._operand(high_value),
                        self._operand(low_value),
                        operation.origin,
                    )
                )
                env[output.id] = _Residual(residual)
            case Load(output=output, address=address):
                env[output.id] = self._load(
                    state, operation, self._value(env, address), rblock, record
                )
            case Store(address=address, value=stored):
                self._store(
                    state,
                    operation,
                    self._value(env, address),
                    self._value(env, stored),
                    rblock,
                    record,
                )
            case Call():
                self._call(state, operation, rblock, record)
            case UserOp(output=output, inputs=inputs):
                residual_output = None if output is None else self._var(output.width)
                emit(
                    UserOp(
                        operation.name,
                        residual_output,
                        tuple(self._operand(self._value(env, value)) for value in inputs),
                        operation.origin,
                    )
                )
                if output is not None and residual_output is not None:
                    env[output.id] = _Residual(residual_output)
            case Unsupported(output=output, inputs=inputs):
                residual_output = None if output is None else self._var(output.width)
                emit(
                    Unsupported(
                        operation.pcode_opcode,
                        residual_output,
                        tuple(self._operand(self._value(env, value)) for value in inputs),
                        operation.reason,
                        operation.origin,
                    )
                )
                if output is not None and residual_output is not None:
                    env[output.id] = _Residual(residual_output)

    def _load(
        self, state: _State, operation: Load, address: _Value, rblock: int, record: _Record | None
    ) -> _Value:
        width = operation.output.width
        if isinstance(address, _Known):
            known = self._memory(state, address.value, width, record)
            if known is not None:
                self._use(address)
                if operation.origin.address in self.interpreter.fetches and isinstance(
                    known, _Known
                ):
                    self.fetched[address.value] = known.value
                return known
        residual = self._var(width)
        self.blocks[rblock].operations.append(
            Load(residual, self._operand(address), operation.origin)
        )
        return _Residual(residual)

    def _memory(
        self, state: _State, address: int, width: int, record: _Record | None
    ) -> _Value | None:
        """The value at `address`, when this path knows it."""
        size = width // 8
        cells = range(address, address + size)
        fact = state.memory.facts.get(address)
        if fact is not None and fact[0] == width:
            if record is not None and any(cell in state.memory.carried for cell in cells):
                self.iteration_reads.update(cells)
            return fact[1]
        read_only = _read_only(self.module, address, size)
        if read_only is not None:
            if record is not None:
                record.bytecode.extend(cells)
            return _Known(read_only, width)
        memory = state.memory
        if memory.clobbered or any(cell in memory.written for cell in cells):
            return None
        if record is not None:
            if self.assumptions.iterations_clobber or any(
                cell in self.assumptions.varying_cells for cell in cells
            ):
                return None
            self.iteration_reads.update(cells)
        value = self.entry.memory(address, width)
        if value is None:
            return None
        fact_key: _Fact = (None, address, width)
        self.facts[fact_key] = value
        return _Known(value, width, frozenset({fact_key}))

    def _store(
        self,
        state: _State,
        operation: Store,
        address: _Value,
        value: _Value,
        rblock: int,
        record: _Record | None,
    ) -> None:
        self.blocks[rblock].operations.append(
            Store(self._operand(address), self._operand(value), operation.origin)
        )
        width = operation.value.width
        if isinstance(address, _Known):
            state.memory.store(address.value, width, value)
            if record is not None:
                self.iteration_writes.update(range(address.value, address.value + width // 8))
            return
        state.memory.clobber()
        if record is not None:
            self.iteration_clobbers = True

    def _call(self, state: _State, call: Call, rblock: int, record: _Record | None) -> None:
        env = state.env
        target = call.target
        if isinstance(target, IndirectTarget):
            target = IndirectTarget(
                self._operand(self._value(env, target.address)), target.candidates
            )
        results = tuple(self._var(result.width) for result in call.results)
        self.blocks[rblock].operations.append(
            Call(
                target,
                call.argument_registers,
                tuple(self._operand(self._value(env, value)) for value in call.arguments),
                call.result_registers,
                results,
                call.origin,
            )
        )
        for native, residual in zip(call.results, results, strict=True):
            env[native.id] = _Residual(residual)
        state.memory.clobber()
        if record is not None:
            self.iteration_clobbers = True

    def _terminator(
        self, state: _State, block: Block, rblock: int, record: _Record | None
    ) -> int | list[_Walk]:
        """The next native block on this path, or the walks it forks into (none if it ends)."""
        env = state.env
        residual = self.blocks[rblock]
        terminator = block.terminator
        match terminator:
            case Jump(target=target):
                return target
            case Branch(condition=condition, true_target=true_target, false_target=false_target):
                decided = self._value(env, condition)
                if isinstance(decided, _Known):
                    self._use(decided)
                    return true_target if decided.value else false_target
                chooser = decided.var
                origin = terminator.origin
                return self._fork(
                    state,
                    block,
                    rblock,
                    record,
                    [true_target, false_target],
                    lambda blocks: Branch(chooser, blocks[0], blocks[1], origin),
                )
            case IndirectJump(address=address, targets=targets):
                decided = self._value(env, address)
                if isinstance(decided, _Known):
                    self._use(decided)
                    found = dict(targets).get(decided.value)
                    if found is not None:
                        return found
                    residual.terminator = Stop(
                        f"indirect jump to unrecovered target {decided.value:#x}", terminator.origin
                    )
                    return []
                jump_address = decided.var
                origin = terminator.origin
                return self._fork(
                    state,
                    block,
                    rblock,
                    record,
                    [target for _, target in targets],
                    lambda blocks: IndirectJump(
                        jump_address,
                        tuple((value, blocks[index]) for index, (value, _) in enumerate(targets)),
                        origin,
                    ),
                )
            case Return(values=values, return_address=return_address):
                residual.terminator = Return(
                    tuple(self._operand(self._value(env, value)) for value in values),
                    None
                    if return_address is None
                    else self._operand(self._value(env, return_address)),
                    terminator.origin,
                )
                if record is not None:
                    record.exits.append("returns")
                return []
            case TailCall():
                raise SpecializationError(
                    f"tail call at {terminator.origin.address:#x} inside the interpreter"
                )
            case Halt():
                residual.terminator = Halt(terminator.origin)
                if record is not None:
                    record.exits.append("halts")
                return []
            case Stop(reason=reason):
                residual.terminator = Stop(reason, terminator.origin)
                if record is not None:
                    record.exits.append(f"stops: {reason}")
                return []

    def _fork(
        self,
        state: _State,
        block: Block,
        rblock: int,
        record: _Record | None,
        targets: list[int],
        terminator: Callable[[list[int]], Terminator],
    ) -> list[_Walk]:
        walks: list[_Walk] = []
        blocks: list[int] = []
        for target in targets:
            branch = self._new_block(self.function.blocks[target].address)
            blocks.append(branch)
            walks.append(_Walk(state.copy(), target, block.id, branch, record))
        self.blocks[rblock].terminator = terminator(blocks)
        return walks

    # -- the dispatch loop -------------------------------------------------------------------

    def _arrive(
        self, state: _State, predecessor: int, rblock: int, record: _Record | None
    ) -> list[_Walk]:
        incoming = {
            phi.output.id: self._value(state.env, dict(phi.incoming)[predecessor])
            for phi in self.header.phis
        }
        counter = self._counter(state, incoming)
        known: list[int] = []
        for phi in self.header.phis:
            if phi.output.id in self.assumptions.general_phis:
                continue
            value = incoming[phi.output.id]
            if not isinstance(value, _Known):
                self.assumptions.general_phis.add(phi.output.id)
                raise _RestartError
            self._use(value)
            known.append(value.value)
        cells: list[tuple[int, int, int]] = []
        for start, (width, value) in sorted(state.memory.facts.items()):
            if isinstance(value, _Known) and start not in self.assumptions.general_cells:
                self._use(value)
                cells.append((start, width, value.value))
        key = (counter.value, tuple(known), tuple(cells))
        keys = self.keys.setdefault(counter.value, set())
        keys.add(key[1:])
        if len(keys) > MAX_KEYS_PER_COUNTER:
            self._generalize(keys)
        if record is not None and counter.value not in record.successors:
            record.successors.append(counter.value)
        walks: list[_Walk] = []
        target = self.specialized.get(key)
        if target is None:
            target = self._new_block(self.header.address)
            self.specialized[key] = target
            new_record = _Record(counter.value, target)
            self.records.append(new_record)
            walks.append(
                _Walk(
                    self._iteration_state(state, incoming, counter, target),
                    self.header.id,
                    None,
                    target,
                    new_record,
                )
            )
        general = [
            phi for phi in self.header.phis if phi.output.id in self.assumptions.general_phis
        ]
        for phi, (_, sources) in zip(general, self.blocks[target].phis, strict=True):
            sources.append((rblock, self._operand(incoming[phi.output.id])))
        self.blocks[rblock].terminator = Jump(target, Origin(self.header.address, 0))
        return walks

    def _generalize(self, keys: set[_LoopKey]) -> None:
        """Too many variants at one program counter: forget what differs between them."""
        known = [
            phi for phi in self.header.phis if phi.output.id not in self.assumptions.general_phis
        ]
        for index, phi in enumerate(known):
            if len({phis[index] for phis, _ in keys}) > 1:
                self.assumptions.general_phis.add(phi.output.id)
        values: dict[int, set[int | None]] = {}
        for _, cells in keys:
            present = {start: value for start, _, value in cells}
            for start in {start for _, other in keys for start, _, _ in other}:
                values.setdefault(start, set()).add(present.get(start))
        self.assumptions.general_cells |= {start for start, seen in values.items() if len(seen) > 1}
        raise _RestartError

    def _counter(self, state: _State, incoming: dict[int, _Value]) -> _Known:
        match self.interpreter.counter:
            case PhiCounter(phi=phi):
                value = incoming.get(phi)
            case MemoryCounter(location=location, width=width):
                address = self._resolve(state, incoming, location)
                value = None if address is None else self._memory(state, address.value, width, None)
        if not isinstance(value, _Known):
            raise SpecializationError("the VM program counter is not known at the dispatch loop")
        self._use(value)
        return value

    def _resolve(
        self, state: _State, incoming: dict[int, _Value], location: Location
    ) -> _Known | None:
        base, offset = location
        match base:
            case ("const", _):
                return _Known(offset, 64)
            case ("value", int() as identifier):
                value = incoming.get(identifier, state.env.get(identifier))
                if isinstance(value, _Known):
                    return _Known((value.value + offset) & mask(64), 64, value.facts)
                return None
            case ("load", tuple() as inner, int() as width):
                pointer = self._resolve(state, incoming, inner)
                if pointer is None:
                    return None
                loaded = self._memory(state, pointer.value, width, None)
                if isinstance(loaded, _Known):
                    return _Known(
                        (loaded.value + offset) & mask(64), 64, loaded.facts | pointer.facts
                    )
                return None
            case _:
                return None

    def _iteration_state(
        self, state: _State, incoming: dict[int, _Value], counter: _Known, block: int
    ) -> _State:
        """What every trip around the loop at this program counter may assume."""
        env = {
            native: value
            for native, value in state.env.items()
            if self.defined_in.get(native) not in self.loop_body
        }
        for phi in self.header.phis:
            if phi.output.id in self.assumptions.general_phis:
                residual = self._var(phi.output.width)
                self.blocks[block].phis.append((residual, []))
                env[phi.output.id] = _Residual(residual)
            else:
                env[phi.output.id] = incoming[phi.output.id]
        memory = _Memory(written=set(state.memory.written), clobbered=state.memory.clobbered)
        if self.assumptions.iterations_clobber:
            memory.clobbered = True
        else:
            varying = self.assumptions.varying_cells
            for start, (width, value) in state.memory.facts.items():
                cells = range(start, start + width // 8)
                if not any(cell in varying for cell in cells):
                    memory.facts[start] = (width, value)
                    memory.carried.update(cells)
        # Known cells are part of the loop key, so every visit agrees on them.
        for start, (width, value) in state.memory.facts.items():
            if isinstance(value, _Known) and start not in self.assumptions.general_cells:
                memory.store(start, width, value)
        if isinstance(self.interpreter.counter, MemoryCounter):
            address = self._resolve(state, incoming, self.interpreter.counter.location)
            if address is not None:
                memory.store(address.value, self.interpreter.counter.width, counter)
        memory.written = set(state.memory.written)
        return _State(env, memory)

    # -- freezing ----------------------------------------------------------------------------

    def _freeze(
        self,
    ) -> tuple[Function, tuple[Iteration, ...], tuple[Guard, ...], int | None]:
        guards = tuple(
            Guard(register, address, width, value)
            for (register, address, width), value in sorted(
                self.guards.items(),
                key=lambda item: (item[0][0] or "", item[0][1] or 0, item[0][2]),
            )
        )
        origin = Origin(self.function.entry, 0)
        offset = len(guards) + 1 if guards else 0
        blocks: list[Block] = []
        stop = len(guards)
        for index, guard in enumerate(guards):
            operations: list[Operation] = []
            subject: Operand
            if guard.register is not None:
                subject = self._input(guard.register)
            else:
                subject = self._var(guard.width)
                operations.append(Load(subject, Const(guard.address or 0, 64), origin))
            holds = self._var(8)
            operations.append(
                BinaryOp(
                    BinaryOpcode.EQUAL, holds, subject, Const(guard.value, guard.width), origin
                )
            )
            following = index + 1 if index + 1 < len(guards) else offset
            blocks.append(
                Block(
                    index,
                    self.function.entry,
                    (),
                    tuple(operations),
                    Branch(holds, following, stop, origin),
                )
            )
        if guards:
            reason = "the interpreter was entered in a state it was not specialized for"
            blocks.append(Block(stop, self.function.entry, (), (), Stop(reason, origin)))
        for index, residual in enumerate(self.blocks):
            if residual.terminator is None:
                raise SpecializationError(f"residual block {index} was left unfinished")
            blocks.append(
                Block(
                    index + offset,
                    residual.address,
                    tuple(
                        Phi(
                            var,
                            tuple(sorted((source + offset, value) for source, value in sources)),
                        )
                        for var, sources in residual.phis
                    ),
                    tuple(residual.operations),
                    _shift(residual.terminator, offset),
                )
            )
        function = Function(
            name=f"{self.function.name}.bytecode",
            entry=self.function.entry,
            inputs=tuple(
                FunctionInput(item.register, self.inputs[item.value.id])
                for item in self.function.inputs
            ),
            output_registers=self.function.output_registers,
            blocks=tuple(blocks),
        )
        base = self._bytecode_base()
        iterations = tuple(
            self._iteration(record, offset, base)
            for record in sorted(self.records, key=lambda item: (item.counter, item.block))
        )
        return function, iterations, guards, base

    def _bytecode_base(self) -> int | None:
        """The fetch address of program counter zero: the base most fetches agree on."""
        if not self.fetched or not self.records:
            return None
        counters = {record.counter for record in self.records}
        scores: dict[int, int] = {}
        for address in self.fetched:
            for counter in counters:
                base = address - counter
                if base not in scores:
                    scores[base] = sum(1 for other in counters if base + other in self.fetched)
        best = max(scores, key=lambda base: (scores[base], -base))
        return best if scores[best] * 2 >= len(counters) else None

    def _iteration(self, record: _Record, offset: int, base: int | None) -> Iteration:
        opcode = None
        instruction: tuple[int, ...] = ()
        if base is not None:
            start = base + record.counter
            opcode = self.fetched.get(start)
            if opcode is None:
                # Some compilers decode the next opcode before the loop header; the byte
                # is still in read-only bytecode.
                opcode = _read_only(self.module, start, 1)
            # The instruction's bytes: what was read from its own position on, short of
            # the opcodes of the instructions that follow it.
            following = {base + successor for successor in record.successors} - {start}
            instruction = tuple(
                sorted(
                    {
                        address
                        for address in record.bytecode
                        if start <= address < start + _MAX_INSTRUCTION_BYTES
                        and address not in following
                    }
                    | ({start} if opcode is not None else set())
                )
            )
        return Iteration(
            counter=record.counter,
            block=record.block + offset,
            blocks=tuple(block + offset for block in record.blocks),
            opcode=opcode,
            handler=record.handler,
            bytecode=instruction,
            successors=tuple(record.successors),
            exits=tuple(dict.fromkeys(record.exits)),
        )

    def _input(self, register: str) -> Var:
        for item in self.function.inputs:
            if item.register == register:
                return self.inputs[item.value.id]
        raise SpecializationError(f"the interpreter has no input register {register}")


def _read_only(module: Module, address: int, size: int) -> int | None:
    for region in module.memory:
        if region.start <= address and address + size <= region.end:
            if region.writable or region.data is None:
                return None
            start = address - region.start
            if start + size > len(region.data):
                return None
            return int.from_bytes(region.data[start : start + size], "little")
    return None


def _shift(terminator: Terminator, offset: int) -> Terminator:
    match terminator:
        case Jump(target=target):
            return Jump(target + offset, terminator.origin)
        case Branch(condition=condition, true_target=true_target, false_target=false_target):
            return Branch(condition, true_target + offset, false_target + offset, terminator.origin)
        case IndirectJump(address=address, targets=targets):
            return IndirectJump(
                address,
                tuple((value, block + offset) for value, block in targets),
                terminator.origin,
            )
        case _:
            return terminator

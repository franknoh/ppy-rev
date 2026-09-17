"""Finding bytecode interpreters: loops that fetch an opcode and dispatch on it.

A dispatcher is a group of branches (a jump table, or a chain or tree of comparisons)
that all decide on one selector value, fanning out to many handler blocks. It is a VM
dispatcher when the selector is fetched from memory at an index the loop keeps updating
(the VM program counter), the handlers return to the loop, and the loop decodes
instructions: handlers advance the program counter by different amounts, or read operands
after the opcode. A loop that steps through its input one element at a time and branches on
each (a character classifier) has everything else.

Every candidate carries its evidence, each marked as proven from RevIR, inferred, or a
heuristic guess, and a confidence score. Opcode-to-handler mappings are proven by
evaluating the dispatch branches for each opcode value.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from ppy_rev.analysis.locations import CONSTANT, Location, Locations, with_offset
from ppy_rev.ir import semantics
from ppy_rev.ir.cfg import ControlFlow, control_flow
from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Block,
    Branch,
    Call,
    Const,
    Function,
    IndirectJump,
    Jump,
    Load,
    MemoryRegion,
    Module,
    Operand,
    Phi,
    Piece,
    Store,
    Subpiece,
    UnaryOp,
    UnaryOpcode,
    Var,
    mask,
    operation_inputs,
    operation_output,
)

_SYMBOLS = {
    BinaryOpcode.ADD: "+",
    BinaryOpcode.SUB: "-",
    BinaryOpcode.MUL: "*",
    BinaryOpcode.AND: "&",
    BinaryOpcode.OR: "|",
    BinaryOpcode.XOR: "^",
    BinaryOpcode.SHIFT_LEFT: "<<",
}
LIKELY_DISPATCHER = 0.6
"""Confidence from which a candidate is reported as a VM dispatcher by default."""
_UNSTRUCTURED = 0.6
"""Scales the confidence of a loop without instruction structure below `LIKELY_DISPATCHER`."""
_SAME_DEPTH = 6
MIN_HANDLERS = 4
MAX_OPCODE_VALUES = 256
_TABLE_ENTRY_BITS = 16


class Certainty(StrEnum):
    PROVEN = "proven"
    INFERRED = "inferred"
    HEURISTIC = "heuristic"


@dataclass(frozen=True, slots=True)
class Evidence:
    certainty: Certainty
    text: str


@dataclass(frozen=True, slots=True)
class Handler:
    block: int
    address: int
    opcodes: tuple[int, ...]
    """Opcode values proven to select this handler (empty if none could be evaluated)."""
    returns_to_dispatcher: bool


@dataclass(frozen=True, slots=True)
class OpcodeFetch:
    instructions: tuple[int, ...]
    """Instructions loading the opcode."""
    width: int
    address: str
    """How the fetch address is formed, e.g. `0x102060 + zext([RDI]:32)`."""
    bytecode_base: int | None
    """A constant base the fetch indexes from, when there is one."""
    bytecode_region: str | None
    program_counter: str | None
    """Where the VM program counter lives, when the fetch index loads it from memory."""
    program_counter_location: Location | None
    """The memory location of a program counter kept in memory."""
    program_counter_phi: int | None = None
    """The loop phi holding a program counter kept in a register."""


@dataclass(frozen=True, slots=True)
class _Instructions:
    """Signs that the dispatch loop decodes instructions rather than walking data."""

    varying_advance: bool
    """The program counter advances differently depending on the handler."""
    operand_readers: int
    """Handlers that read from the bytecode at an index other than the opcode's."""

    @property
    def found(self) -> bool:
        return self.varying_advance or self.operand_readers > 0


@dataclass(frozen=True, slots=True)
class Dispatcher:
    function: str
    function_entry: int
    address: int
    """The first dispatch block."""
    blocks: tuple[int, ...]
    loop_header: int | None
    fetch: OpcodeFetch | None
    handlers: tuple[Handler, ...]
    confidence: float
    evidence: tuple[Evidence, ...]


def detect_dispatchers(module: Module) -> list[Dispatcher]:
    """Dispatcher candidates in every function, most confident first."""
    found: list[Dispatcher] = []
    for function in module.functions:
        found.extend(_FunctionDispatchers(module, function).find())
    found.sort(key=lambda candidate: (-candidate.confidence, candidate.address))
    return found


type _Key = tuple[str, int] | tuple[str, Location]
"""A selector: a phi or other value, or a memory location every load of which is the same."""


class _FunctionDispatchers:
    def __init__(self, module: Module, function: Function) -> None:
        self.module = module
        self.function = function
        self.flow: ControlFlow = control_flow(function)
        self.locations = Locations(function)
        self.definitions = self.locations.definitions
        self.input_names = {item.value.id: item.register for item in function.inputs}
        self._phi_keys: dict[int, _Key] = {}
        self._visiting_slots: set[Location] = set()
        self._visiting: set[int] = set()
        self.stack_pointer = next(
            (
                item.value.id
                for item in function.inputs
                if item.register == module.target.stack_pointer
            ),
            None,
        )
        self.stores: list[Store] = [
            operation
            for block in function.blocks
            for operation in block.operations
            if isinstance(operation, Store)
        ]

    # -- selectors ---------------------------------------------------------------------------

    def leaves(
        self, operand: Operand, through_tables: bool = False, merge_phis: bool = True
    ) -> set[_Key]:
        """The non-constant sources `operand` is a pure function of.

        With `through_tables`, a wide load from read-only memory at an address computed
        from other values (a jump table entry) is part of that function; any other load is
        a source, keyed by its location. Byte loads stay sources: they are how opcodes are
        fetched from bytecode.
        """
        found: set[_Key] = set()
        seen: set[int] = set()
        work = [operand]
        while work:
            current = work.pop()
            if isinstance(current, Const) or current.id in seen:
                continue
            seen.add(current.id)
            definition = self.definitions.get(current.id)
            match definition:
                case BinaryOp() | UnaryOp() | Subpiece() | Piece():
                    work.extend(operation_inputs(definition))
                case Load(address=address) if (
                    through_tables
                    and definition.output.width >= _TABLE_ENTRY_BITS
                    and self._read_only_table(address)
                ):
                    work.append(address)
                case Load(address=address):
                    found.add(self._load_key(self.locations.of(address)))
                case Phi() if merge_phis:
                    found.add(self._phi_key(current.id))
                case _:
                    found.add(("value", current.id))
        return found

    def _load_key(self, location: Location) -> _Key:
        """A stack slot that only ever holds one selector is keyed as that selector."""
        own: _Key = ("load", location)
        if not self._is_stack_slot(location) or location in self._visiting_slots:
            return own
        stores = self._stores_at(location)
        if not stores:
            return own
        self._visiting_slots.add(location)
        stored: set[_Key] = set()
        for store in stores:
            stored |= self.leaves(store.value)
        self._visiting_slots.discard(location)
        return next(iter(stored)) if len(stored) == 1 and own not in stored else own

    def _phi_key(self, identifier: int) -> _Key:
        """A phi joining one source with constants is keyed as that source.

        Compilers move part of a dispatch to the fetch and carry the results around the
        loop in phis; the phi then stands for the same selector.
        """
        cached = self._phi_keys.get(identifier)
        if cached is not None:
            return cached
        if identifier in self._visiting:
            return ("cycle", identifier)
        self._visiting.add(identifier)
        definition = self.definitions[identifier]
        keys: set[_Key] = set()
        if isinstance(definition, Phi):
            for _, value in definition.incoming:
                keys |= self.leaves(value)
        self._visiting.discard(identifier)
        keys.discard(("cycle", identifier))
        own: _Key = ("value", identifier)
        result = next(iter(keys)) if len(keys) == 1 else own
        if result[0] == "cycle":
            result = own
        self._phi_keys[identifier] = result
        return result

    def _read_only_table(self, address: Operand) -> bool:
        base, offset = self.locations.of(address)
        if base == CONSTANT:
            return False  # a fixed global, not a table indexed by the selector
        region = _region_at(self.module, offset)
        return region is not None and not region.writable and region.data is not None

    def selector(self, block: Block) -> _Key | None:
        terminator = block.terminator
        match terminator:
            case Branch(condition=condition):
                leaves = self.leaves(condition)
            case IndirectJump(address=address):
                leaves = self.leaves(address, through_tables=True)
            case _:
                return None
        return next(iter(leaves)) if len(leaves) == 1 else None

    # -- groups ------------------------------------------------------------------------------

    def find(self) -> list[Dispatcher]:
        keyed = {
            block.id: key
            for block in self.function.blocks
            if self.flow.reachable(block.id) and (key := self.selector(block)) is not None
        }
        # Dispatch groups are connected components of blocks deciding on the same selector.
        parent = {block_id: block_id for block_id in keyed}

        def root(block_id: int) -> int:
            while parent[block_id] != block_id:
                parent[block_id] = parent[parent[block_id]]
                block_id = parent[block_id]
            return block_id

        members: dict[int, set[int]] = {}
        for block_id, key in keyed.items():
            for successor in self._same_key_successors(block_id, key, keyed):
                parent[root(successor)] = root(block_id)
        for block_id in keyed:
            members.setdefault(root(block_id), set()).add(block_id)
        candidates: list[Dispatcher] = []
        for group in members.values():
            key = keyed[next(iter(group))]
            group |= self._pass_through_blocks(group, key, keyed)
            candidate = self._candidate(group, key)
            if candidate is not None:
                candidates.append(candidate)
        return candidates

    def _same_key_successors(self, block_id: int, key: _Key, keyed: dict[int, _Key]) -> list[int]:
        """Keyed successors with the same selector, directly or through pass-through blocks."""
        found: list[int] = []
        seen: set[int] = set()
        work = list(self.flow.successors[block_id])
        while work:
            successor = work.pop()
            if successor in seen:
                continue
            seen.add(successor)
            if keyed.get(successor) == key:
                found.append(successor)
            elif self._passes_through(successor, key, keyed):
                work.extend(self.flow.successors[successor])
        return found

    def _pass_through_blocks(self, group: set[int], key: _Key, keyed: dict[int, _Key]) -> set[int]:
        return {
            successor
            for block_id in group
            for successor in self.flow.successors[block_id]
            if successor not in group and self._passes_through(successor, key, keyed)
        }

    def _passes_through(
        self, block_id: int, key: _Key, keyed: dict[int, _Key], depth: int = 0
    ) -> bool:
        """A block that only recomputes the selector and jumps on to more dispatching."""
        block = self.function.blocks[block_id]
        if not isinstance(block.terminator, Jump) or block.phis or depth > len(keyed):
            return False
        target = block.terminator.target
        if keyed.get(target) != key and not self._passes_through(target, key, keyed, depth + 1):
            return False
        for operation in block.operations:
            if isinstance(operation, Store | Call):
                return False
            for output in operation_output(operation):
                if not self.leaves(output) <= {key}:
                    return False
        return True

    # -- candidates --------------------------------------------------------------------------

    def _candidate(self, group: set[int], key: _Key) -> Dispatcher | None:
        exits = sorted(
            {
                successor
                for block_id in group
                for successor in self.flow.successors[block_id]
                if successor not in group
            }
        )
        if len(exits) < MIN_HANDLERS:
            return None
        entry = min(group, key=self.flow.reverse_postorder.index)
        fetch = self._fetch(key)
        mapping = self._opcode_mapping(entry, group, key, fetch)
        header = self._loop_header(group)
        body = self._loop_body(header) if header is not None else set[int]()
        handlers = tuple(
            Handler(
                block=exit_id,
                address=self.function.blocks[exit_id].address,
                opcodes=tuple(sorted(mapping.get(exit_id, ()))),
                returns_to_dispatcher=header is not None
                and exit_id in body
                and self._reaches(exit_id, group | {header}, body),
            )
            for exit_id in exits
        )
        instructions = self._instructions(fetch, handlers, header)
        evidence = self._evidence(group, key, fetch, handlers, header, instructions)
        return Dispatcher(
            function=self.function.name,
            function_entry=self.function.entry,
            address=self.function.blocks[entry].address,
            blocks=tuple(sorted(group)),
            loop_header=None if header is None else self.function.blocks[header].address,
            fetch=fetch,
            handlers=handlers,
            confidence=_confidence(fetch, handlers, header, group, self.function, instructions),
            evidence=evidence,
        )

    def _fetch_loads(self, key: _Key) -> list[Load]:
        """The loads that produce the selector: directly, through phis, or via a slot."""
        loads: list[Load] = []
        seen: set[_Key] = set()
        work: list[_Key] = [key]
        while work:
            current = work.pop()
            if current in seen:
                continue
            seen.add(current)
            match current:
                case ("value", int() as identifier):
                    definition = self.definitions.get(identifier)
                    if isinstance(definition, Phi):
                        for _, value in definition.incoming:
                            work.extend(self.leaves(value))
                case ("load", tuple() as location):
                    stored = self._stores_at(location)
                    if stored:
                        for store in stored:
                            work.extend(self.leaves(store.value))
                    else:
                        loads.extend(self._loads_at(location))
                case _:
                    pass
        return loads

    def _stores_at(self, location: Location) -> list[Store]:
        return [store for store in self.stores if self.locations.of(store.address) == location]

    def _loads_at(self, location: Location) -> list[Load]:
        return [
            operation
            for block in self.function.blocks
            for operation in block.operations
            if isinstance(operation, Load) and self.locations.of(operation.address) == location
        ]

    def _fetch(self, key: _Key) -> OpcodeFetch | None:
        loads = self._fetch_loads(key)
        if not loads:
            return None
        first = loads[0]
        base, offset = self.locations.of(first.address)
        region = _region_at(self.module, offset) if base != CONSTANT else None
        has_base = region is not None and region.data is not None
        counter = self._program_counter(first.address)
        return OpcodeFetch(
            instructions=tuple(sorted({load.origin.address for load in loads})),
            width=first.output.width,
            address=self.render(first.address),
            bytecode_base=offset if has_base else None,
            bytecode_region=region.name if has_base and region is not None else None,
            program_counter=None if counter is None else counter[0],
            program_counter_location=None if counter is None else counter[1],
            program_counter_phi=None if counter is None else counter[2],
        )

    def _is_stack_slot(self, location: Location) -> bool:
        return location[0] == ("value", self.stack_pointer) if self.stack_pointer else False

    def _index_sources(self, operand: Operand) -> set[_Key]:
        """Leaves of `operand`, looking through stack slots to the values stored there."""
        sources: set[_Key] = set()
        seen: set[_Key] = set()
        work = list(self.leaves(operand, merge_phis=False))
        while work:
            leaf = work.pop()
            if leaf in seen:
                continue
            seen.add(leaf)
            match leaf:
                case ("load", tuple() as location) if self._is_stack_slot(location) and (
                    stores := self._stores_at(location)
                ):
                    stored: set[_Key] = set()
                    for store in stores:
                        stored |= self.leaves(store.value)
                    if leaf in stored:
                        sources.add(leaf)  # a local variable updated from itself
                    else:
                        work.extend(stored)
                case _:
                    sources.add(leaf)
        return sources

    def describe_location(self, location: Location) -> str:
        """Like `Locations.describe`, naming a pointer kept in a stack slot by its value."""
        base, offset = location
        match base:
            case ("load", tuple() as slot, int()) if self._is_stack_slot(slot):
                stores = self._stores_at(slot)
                if len(stores) == 1:
                    return with_offset(self.render(stores[0].value), offset)
            case _:
                pass
        return self.locations.describe(location)

    def _program_counter(self, address: Operand) -> tuple[str, Location | None, int | None] | None:
        """The fetch index the loop updates: a written memory field or a loop variable.

        Values loaded from memory the function never writes (a bytecode pointer) are not
        candidates.
        """
        sources = self._index_sources(address)
        written = [
            location
            for leaf in sources
            if leaf[0] == "load" and isinstance(location := leaf[1], tuple)
            if self._stores_at(location)
        ]
        if len(written) == 1:
            location = written[0]
            widths = {load.output.width for load in self._loads_at(location)}
            width = f":{min(widths)}" if widths else ""
            return f"[{self.describe_location(location)}]{width}", location, None
        loop_values = [
            identifier
            for leaf in sources
            if leaf[0] == "value" and isinstance(identifier := leaf[1], int)
            if isinstance(self.definitions.get(identifier), Phi)
        ]
        if not written and len(loop_values) == 1:
            return f"loop variable v{loop_values[0]}", None, loop_values[0]
        return None

    def render(self, operand: Operand, depth: int = 4) -> str:
        """A short expression for `operand`, seeing through stack slots."""
        if isinstance(operand, Const):
            return f"{operand.value:#x}"
        name = self.input_names.get(operand.id)
        if name is not None:
            return name
        definition = self.definitions.get(operand.id)
        if depth <= 0 or definition is None:
            return f"v{operand.id}"
        match definition:
            case BinaryOp(opcode=opcode, left=left, right=right) if opcode in _SYMBOLS:
                symbol = _SYMBOLS[opcode]
                return f"({self.render(left, depth - 1)} {symbol} {self.render(right, depth - 1)})"
            case UnaryOp(opcode=UnaryOpcode.ZERO_EXTEND | UnaryOpcode.SIGN_EXTEND, operand=inner):
                return self.render(inner, depth)
            case Load(address=address):
                location = self.locations.of(address)
                stores = self._stores_at(location) if self._is_stack_slot(location) else []
                if len(stores) == 1:
                    return self.render(stores[0].value, depth - 1)
                return f"[{self.render(address, depth - 1)}]:{definition.output.width}"
            case _:
                return f"v{operand.id}"

    # -- opcode mapping ----------------------------------------------------------------------

    def _opcode_mapping(
        self, entry: int, group: set[int], key: _Key, fetch: OpcodeFetch | None
    ) -> dict[int, set[int]]:
        width = fetch.width if fetch is not None else 8
        values: Iterable[int] = (
            range(1 << width) if (1 << width) <= MAX_OPCODE_VALUES else self._constants(group)
        )
        mapping: dict[int, set[int]] = {}
        for value in values:
            target = _DispatchEvaluator(self, key, value).run(entry, group)
            if target is not None:
                mapping.setdefault(target, set()).add(value)
        return mapping

    def _constants(self, group: set[int]) -> list[int]:
        constants: set[int] = set()
        for block_id in group:
            for operation in self.function.blocks[block_id].operations:
                constants.update(
                    operand.value
                    for operand in operation_inputs(operation)
                    if isinstance(operand, Const)
                )
        return sorted(constants)[:MAX_OPCODE_VALUES]

    # -- loops -------------------------------------------------------------------------------

    def _loop_header(self, group: set[int]) -> int | None:
        """The loop holding most of the dispatch group (the innermost, on a tie).

        Parts of a dispatch may sit outside its loop: a first fetch before a rotated loop,
        or an opcode that halts the machine.
        """
        best: tuple[int, int, int] | None = None
        for source, targets in enumerate(self.flow.successors):
            for header in targets:
                if not self.flow.dominates(header, source):
                    continue
                body = self._loop_body(header)
                overlap = len(group & body)
                if overlap and (best is None or (overlap, -len(body)) > (best[1], -best[2])):
                    best = (header, overlap, len(body))
        return None if best is None else best[0]

    def _loop_body(self, header: int) -> set[int]:
        body = {header}
        work = [
            source
            for source, targets in enumerate(self.flow.successors)
            if header in targets and self.flow.dominates(header, source)
        ]
        while work:
            block_id = work.pop()
            if block_id in body:
                continue
            body.add(block_id)
            work.extend(self.flow.predecessors[block_id])
        return body

    def _reaches(self, start: int, targets: set[int], within: set[int]) -> bool:
        seen = {start}
        work = [start]
        while work:
            block_id = work.pop()
            for successor in self.flow.successors[block_id]:
                if successor in targets:
                    return True
                if successor in within and successor not in seen:
                    seen.add(successor)
                    work.append(successor)
        return False

    # -- instruction structure ---------------------------------------------------------------

    def _instructions(
        self, fetch: OpcodeFetch | None, handlers: tuple[Handler, ...], header: int | None
    ) -> _Instructions:
        counter = _counter_key(fetch)
        if fetch is None or header is None or counter is None:
            return _Instructions(varying_advance=False, operand_readers=0)
        body = self._loop_body(header)
        distinct: list[Operand] = []
        for update in self._counter_updates(fetch, body):
            if not any(self._same_value(update, known) for known in distinct):
                distinct.append(update)
        varying = len(distinct) > 1
        if fetch.program_counter_location is not None:
            # Unoptimized code advances a counter in memory by repeating the same increment.
            returning = [handler for handler in handlers if handler.returns_to_dispatcher]
            writers = self._counter_writers(fetch, tuple(returning))
            varying = varying or 0 < writers < len(returning)
        fetches = [
            operation
            for block in self.function.blocks
            for operation in block.operations
            if isinstance(operation, Load) and operation.origin.address in fetch.instructions
        ]
        readers = sum(
            1 for handler in handlers if self._reads_operand(handler, counter, fetches, header)
        )
        return _Instructions(varying_advance=varying, operand_readers=readers)

    def _counter_updates(self, fetch: OpcodeFetch, body: set[int]) -> list[Operand]:
        """The values the program counter takes on the way around the loop, through phis."""
        phi_blocks = {
            phi.output.id: block.id for block in self.function.blocks for phi in block.phis
        }
        work: list[Operand] = []
        if fetch.program_counter_phi is not None:
            definition = self.definitions.get(fetch.program_counter_phi)
            if isinstance(definition, Phi):
                work.extend(value for source, value in definition.incoming if source in body)
        elif fetch.program_counter_location is not None:
            work.extend(
                operation.value
                for block_id in sorted(body)
                for operation in self.function.blocks[block_id].operations
                if isinstance(operation, Store)
                and self.locations.of(operation.address) == fetch.program_counter_location
            )
        updates: list[Operand] = []
        seen: set[int] = set()
        while work:
            value = self._peel(work.pop())
            if isinstance(value, Const):
                updates.append(value)
                continue
            if value.id in seen:
                continue
            seen.add(value.id)
            definition = self.definitions.get(value.id)
            if (
                isinstance(definition, Phi)
                and value.id != fetch.program_counter_phi
                and phi_blocks.get(value.id) in body
            ):
                work.extend(item for source, item in definition.incoming if source in body)
            else:
                updates.append(value)
        return updates

    def _reads_operand(
        self, handler: Handler, counter: _Key, fetches: list[Load], header: int
    ) -> bool:
        """The handler loads from an address indexed by the program counter, not the opcode's."""
        if handler.block == header:
            return False
        for block_id in self._handler_blocks(handler.block):
            for operation in self.function.blocks[block_id].operations:
                if (
                    isinstance(operation, Load)
                    and operation not in fetches
                    and counter in self._index_sources(operation.address)
                    and not any(
                        self._same_value(operation.address, fetched.address) for fetched in fetches
                    )
                ):
                    return True
        return False

    def _same_value(self, left: Operand, right: Operand, depth: int = _SAME_DEPTH) -> bool:
        """Whether two operands are computed the same way (reloading the same location).

        Widening and truncation are ignored: they do not change how far a counter moves.
        """
        left, right = self._peel(left), self._peel(right)
        if isinstance(left, Const) or isinstance(right, Const):
            return left == right
        if left.id == right.id:
            return True
        if depth == 0:
            return False
        first, second = self.definitions.get(left.id), self.definitions.get(right.id)
        if isinstance(first, BinaryOp) and isinstance(second, BinaryOp):
            return (
                first.opcode is second.opcode
                and self._same_value(first.left, second.left, depth - 1)
                and self._same_value(first.right, second.right, depth - 1)
            )
        if isinstance(first, UnaryOp) and isinstance(second, UnaryOp):
            return first.opcode is second.opcode and self._same_value(
                first.operand, second.operand, depth - 1
            )
        if isinstance(first, Subpiece) and isinstance(second, Subpiece):
            return first.low_bit == second.low_bit and self._same_value(
                first.operand, second.operand, depth - 1
            )
        if isinstance(first, Load) and isinstance(second, Load):
            return first.output.width == second.output.width and (
                self.locations.of(first.address) == self.locations.of(second.address)
                or self._same_value(first.address, second.address, depth - 1)
            )
        return False

    def _peel(self, operand: Operand) -> Operand:
        """`operand` without the extensions and truncations around it."""
        while isinstance(operand, Var):
            match self.definitions.get(operand.id):
                case UnaryOp(
                    opcode=UnaryOpcode.ZERO_EXTEND | UnaryOpcode.SIGN_EXTEND | UnaryOpcode.TRUNCATE,
                    operand=inner,
                ):
                    operand = inner
                case Subpiece(low_bit=0, operand=inner):
                    operand = inner
                case _:
                    break
        return operand

    # -- evidence ----------------------------------------------------------------------------

    def _evidence(
        self,
        group: set[int],
        key: _Key,
        fetch: OpcodeFetch | None,
        handlers: tuple[Handler, ...],
        header: int | None,
        instructions: _Instructions,
    ) -> tuple[Evidence, ...]:
        evidence: list[Evidence] = []
        tables = [
            block
            for block_id in sorted(group)
            if isinstance((block := self.function.blocks[block_id]).terminator, IndirectJump)
        ]
        for block in tables:
            terminator = block.terminator
            if isinstance(terminator, IndirectJump):
                count = len({target for _, target in terminator.targets})
                evidence.append(
                    Evidence(
                        Certainty.PROVEN,
                        f"indirect branch at {terminator.origin.address:#x} with {count} targets",
                    )
                )
        comparisons = sum(
            1 for block_id in group if isinstance(self.function.blocks[block_id].terminator, Branch)
        )
        if comparisons:
            evidence.append(
                Evidence(Certainty.PROVEN, f"{comparisons} conditional branches on the same value")
            )
        evidence.append(
            Evidence(
                Certainty.PROVEN,
                f"{len(handlers)} successor blocks are selected by {_describe_key(self, key)}",
            )
        )
        mapped = sum(1 for handler in handlers if handler.opcodes)
        if mapped:
            evidence.append(
                Evidence(
                    Certainty.PROVEN,
                    f"evaluating the dispatch maps opcode values to {mapped} handlers",
                )
            )
        if fetch is not None:
            evidence.append(
                Evidence(
                    Certainty.INFERRED,
                    f"{fetch.width}-bit opcode fetched from {fetch.address}",
                )
            )
            if fetch.bytecode_base is not None:
                where = f" in {fetch.bytecode_region}" if fetch.bytecode_region else ""
                evidence.append(
                    Evidence(
                        Certainty.HEURISTIC,
                        f"bytecode starts near {fetch.bytecode_base:#x}{where}",
                    )
                )
            if fetch.program_counter_location is not None:
                writers = self._counter_writers(fetch, handlers)
                evidence.append(
                    Evidence(
                        Certainty.INFERRED,
                        f"VM program counter is {fetch.program_counter}, written by "
                        f"{writers} of {len(handlers)} handlers",
                    )
                )
            elif fetch.program_counter is not None:
                evidence.append(
                    Evidence(
                        Certainty.INFERRED,
                        f"VM program counter is {fetch.program_counter}, carried around the loop",
                    )
                )
        if header is not None:
            returning = sum(1 for handler in handlers if handler.returns_to_dispatcher)
            evidence.append(
                Evidence(
                    Certainty.PROVEN,
                    f"{returning} of {len(handlers)} handlers return to the dispatch loop "
                    f"at {self.function.blocks[header].address:#x}",
                )
            )
        if instructions.varying_advance:
            evidence.append(
                Evidence(
                    Certainty.INFERRED,
                    "handlers advance the VM program counter by different amounts",
                )
            )
        if instructions.operand_readers:
            evidence.append(
                Evidence(
                    Certainty.INFERRED,
                    f"{instructions.operand_readers} handlers read operands from the bytecode",
                )
            )
        if header is not None and not instructions.found:
            evidence.append(
                Evidence(
                    Certainty.HEURISTIC,
                    "no instruction structure (a program counter advanced differently by "
                    "handlers, or operands read after the opcode): may be a loop over data",
                )
            )
        return tuple(evidence)

    def _counter_writers(self, fetch: OpcodeFetch, handlers: tuple[Handler, ...]) -> int:
        location = fetch.program_counter_location
        if location is None:
            return 0
        count = 0
        for handler in handlers:
            region = self._handler_blocks(handler.block)
            if any(
                isinstance(operation, Store) and self.locations.of(operation.address) == location
                for block_id in region
                for operation in self.function.blocks[block_id].operations
            ):
                count += 1
        return count

    def _handler_blocks(self, start: int) -> set[int]:
        """Blocks the handler owns: reachable from it and dominated by it."""
        owned = {start}
        work = [start]
        while work:
            block_id = work.pop()
            for successor in self.flow.successors[block_id]:
                if successor not in owned and self.flow.dominates(start, successor):
                    owned.add(successor)
                    work.append(successor)
        return owned


class _DispatchEvaluator:
    """Follows the dispatch group for one concrete opcode value."""

    def __init__(self, owner: _FunctionDispatchers, key: _Key, value: int) -> None:
        self.owner = owner
        self.key = key
        self.value = value
        self.values: dict[int, int | None] = {}

    def run(self, entry: int, group: set[int]) -> int | None:
        block_id = entry
        for _ in range(len(group) + 1):
            block = self.owner.function.blocks[block_id]
            match block.terminator:
                case Branch(condition=condition, true_target=true_target, false_target=false):
                    decided = self.evaluate(condition)
                    if decided is None:
                        return None
                    next_block = true_target if decided else false
                case IndirectJump(address=address, targets=targets):
                    target = self.evaluate(address)
                    if target is None:
                        return None
                    found = dict(targets).get(target)
                    if found is None:
                        return None
                    next_block = found
                case Jump(target=target):
                    next_block = target
                case _:
                    return None
            if next_block not in group:
                return next_block
            block_id = next_block
        return None

    def evaluate(self, operand: Operand) -> int | None:
        if isinstance(operand, Const):
            return operand.value
        if operand.id in self.values:
            return self.values[operand.id]
        self.values[operand.id] = None  # guards against cycles through phis
        result = self._compute(operand)
        self.values[operand.id] = result
        return result

    def _compute(self, var: Var) -> int | None:
        owner = self.owner
        if self.key == ("value", var.id):
            return self.value & mask(var.width)
        definition = owner.definitions.get(var.id)
        match definition:
            case Phi(incoming=incoming) if owner.leaves(var) == {self.key}:
                # The loop-carried path: the incoming value computed from the selector.
                for _, value in incoming:
                    if not isinstance(value, Const) and self.key in owner.leaves(value):
                        return self.evaluate(value)
                return None
            case Load(address=address):
                if owner.leaves(var) == {self.key}:
                    return self.value & mask(var.width)
                location = self.evaluate(address)
                if location is None:
                    return None
                return _read_constant(owner.module, location, var.width)
            case BinaryOp(opcode=opcode, left=left, right=right):
                left_value, right_value = self.evaluate(left), self.evaluate(right)
                if left_value is None or right_value is None:
                    return None
                try:
                    return semantics.binary(opcode, left_value, right_value, left.width)
                except semantics.DivisionByZeroError:
                    return None
            case UnaryOp(opcode=opcode, operand=inner):
                inner_value = self.evaluate(inner)
                if inner_value is None:
                    return None
                return semantics.unary(opcode, inner_value, inner.width, var.width)
            case Subpiece(operand=inner, low_bit=low_bit):
                inner_value = self.evaluate(inner)
                return (
                    None
                    if inner_value is None
                    else semantics.subpiece(inner_value, low_bit, var.width)
                )
            case Piece(high=high, low=low):
                high_value, low_value = self.evaluate(high), self.evaluate(low)
                if high_value is None or low_value is None:
                    return None
                return semantics.piece(high_value, low_value, low.width)
            case _:
                return None


def _describe_key(owner: _FunctionDispatchers, key: _Key) -> str:
    match key:
        case ("load", tuple() as location):
            return f"the value loaded from {owner.locations.describe(location)}"
        case ("value", int() as identifier):
            return f"value v{identifier}"
        case _:
            return "one value"


def _confidence(
    fetch: OpcodeFetch | None,
    handlers: tuple[Handler, ...],
    header: int | None,
    group: set[int],
    function: Function,
    instructions: _Instructions,
) -> float:
    score = 0.2
    returning = sum(1 for handler in handlers if handler.returns_to_dispatcher)
    if header is not None:
        score += 0.15 + 0.25 * returning / len(handlers)
    if fetch is not None:
        score += 0.15
        if fetch.program_counter is not None:
            score += 0.1
    if any(isinstance(function.blocks[block_id].terminator, IndirectJump) for block_id in group):
        score += 0.05
    if len(handlers) >= 8:
        score += 0.05
    if any(handler.opcodes for handler in handlers):
        score += 0.05
    if fetch is not None and fetch.bytecode_region is not None:
        score += 0.05
    if instructions.found:
        score += 0.05
    else:
        score *= _UNSTRUCTURED
    return round(min(score, 0.99), 2)


def _counter_key(fetch: OpcodeFetch | None) -> _Key | None:
    """The program counter as the index sources of a fetch address name it."""
    if fetch is None:
        return None
    if fetch.program_counter_phi is not None:
        return ("value", fetch.program_counter_phi)
    if fetch.program_counter_location is not None:
        return ("load", fetch.program_counter_location)
    return None


def _region_at(module: Module, address: int) -> MemoryRegion | None:
    for region in module.memory:
        if region.start <= address < region.end:
            return region
    return None


def _read_constant(module: Module, address: int, width: int) -> int | None:
    size = width // 8
    region = _region_at(module, address)
    if region is None or region.writable or region.data is None:
        return None
    offset = address - region.start
    if offset + size > len(region.data):
        return None
    return int.from_bytes(region.data[offset : offset + size], "little")

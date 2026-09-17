"""Acyclic branch regions whose paths can be executed separately and merged.

A branch whose successors all meet again at its immediate post-dominator, through blocks
that form no loop and make no calls, can be explored to that join and its states merged
into one: values that differ become if-then-else expressions over the path conditions.
Loops of such diamonds (a per-character transform, say) then cost one state per
iteration instead of one per combination of choices.
"""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.ir.cfg import immediate_post_dominators
from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Branch,
    Call,
    Const,
    Function,
    IndirectJump,
    IndirectTarget,
    Jump,
    Load,
    Operand,
    Operation,
    Phi,
    Store,
    TailCall,
    Var,
    mask,
    operation_inputs,
    operation_output,
    successors,
)

MAX_REGION_BLOCKS = 32


@dataclass(frozen=True, slots=True)
class MergeRegion:
    branch: int
    join: int
    blocks: frozenset[int]
    """Blocks strictly between the branch and the join."""


class RegionFinder:
    def __init__(self, max_blocks: int = MAX_REGION_BLOCKS) -> None:
        self.max_blocks = max_blocks
        self._post_dominators: dict[int, tuple[int | None, ...]] = {}
        self._regions: dict[tuple[int, int], MergeRegion | None] = {}
        self._addressing: dict[int, frozenset[int]] = {}

    def addressing(self, function: Function) -> frozenset[int]:
        """Values that flow into a memory address or a jump or call target.

        Merging paths that disagree on such a value would make those accesses symbolic.
        """
        known = self._addressing.get(function.entry)
        if known is None:
            known = _addressing(function)
            self._addressing[function.entry] = known
        return known

    def region(self, function: Function, branch: int) -> MergeRegion | None:
        key = (function.entry, branch)
        if key not in self._regions:
            self._regions[key] = self._find(function, branch)
        return self._regions[key]

    def _find(self, function: Function, branch: int) -> MergeRegion | None:
        post_dominators = self._post_dominators.get(function.entry)
        if post_dominators is None:
            post_dominators = immediate_post_dominators(function)
            self._post_dominators[function.entry] = post_dominators
        join = post_dominators[branch]
        if join is None:
            return None
        blocks: set[int] = set()
        work = list(successors(function.blocks[branch].terminator))
        while work:
            block_id = work.pop()
            if block_id == join or block_id in blocks:
                continue
            if block_id == branch or len(blocks) >= self.max_blocks:
                return None
            block = function.blocks[block_id]
            if not isinstance(block.terminator, Jump | Branch | IndirectJump) or any(
                isinstance(operation, Call) for operation in block.operations
            ):
                return None
            blocks.add(block_id)
            work.extend(successors(block.terminator))
        if not _acyclic(function, blocks):
            return None
        return MergeRegion(branch, join, frozenset(blocks))


def _acyclic(function: Function, blocks: set[int]) -> bool:
    done: set[int] = set()
    active: set[int] = set()

    def visit(block_id: int) -> bool:
        if block_id in done:
            return True
        if block_id in active:
            return False
        active.add(block_id)
        for target in successors(function.blocks[block_id].terminator):
            if target in blocks and not visit(target):
                return False
        active.discard(block_id)
        done.add(block_id)
        return True

    return all(visit(block_id) for block_id in sorted(blocks))


type _Base = tuple[str, int] | tuple[str, "_Location", int]
type _Location = tuple[_Base, int]
"""An address as a base and a constant offset; loaded bases are keyed by where they load."""


class _Addressing:
    """Values that flow into memory addresses or jump targets, including through memory.

    A value stored where some address is later loaded from carries into that address, so
    stores and loads are matched by location: a constant offset from a base that is a
    constant, a function value, or the value loaded from another such location (a pointer
    kept in a stack slot at -O0).
    """

    def __init__(self, function: Function) -> None:
        self.definitions: dict[int, Phi | Operation] = {}
        self.stores: list[Store] = []
        self.roots: list[Operand] = []
        for block in function.blocks:
            for phi in block.phis:
                self.definitions[phi.output.id] = phi
            for operation in block.operations:
                for output in operation_output(operation):
                    self.definitions[output.id] = operation
                match operation:
                    case Load(address=address):
                        self.roots.append(address)
                    case Store(address=address):
                        self.roots.append(address)
                        self.stores.append(operation)
                    case Call(target=IndirectTarget(address=address)):
                        self.roots.append(address)
                    case _:
                        pass
            match block.terminator:
                case IndirectJump(address=address):
                    self.roots.append(address)
                case TailCall(call=Call(target=IndirectTarget(address=address))):
                    self.roots.append(address)
                case _:
                    pass
        self._locations: dict[int, _Location] = {}

    def location(self, operand: Operand, depth: int = 0) -> _Location:
        if isinstance(operand, Const):
            return (("const", 0), operand.value)
        known = self._locations.get(operand.id)
        if known is not None:
            return known
        definition = self.definitions.get(operand.id)
        result: _Location
        match definition:
            case BinaryOp(
                opcode=BinaryOpcode.ADD | BinaryOpcode.SUB, left=left, right=Const(value=delta)
            ):
                base, offset = self.location(left, depth + 1)
                sign = 1 if definition.opcode is BinaryOpcode.ADD else -1
                result = (base, (offset + sign * delta) & mask(definition.output.width))
            case Load(address=address) if depth < _LOCATION_DEPTH:
                result = (("load", self.location(address, depth + 1), definition.output.width), 0)
            case _:
                result = (("value", operand.id), 0)
        self._locations[operand.id] = result
        return result

    def solve(self) -> frozenset[int]:
        marked: set[int] = set()
        slots: set[_Location] = set()
        work = [root for root in self.roots if isinstance(root, Var)]
        changed = True
        while changed:
            while work:
                var = work.pop()
                if var.id in marked:
                    continue
                marked.add(var.id)
                match self.definitions.get(var.id):
                    case Phi(incoming=incoming):
                        work.extend(value for _, value in incoming if isinstance(value, Var))
                    case Load(address=address):
                        slots.add(self.location(address))
                    case Call() | None:
                        pass
                    case operation:
                        work.extend(
                            value for value in operation_inputs(operation) if isinstance(value, Var)
                        )
            changed = False
            for store in self.stores:
                value = store.value
                if (
                    isinstance(value, Var)
                    and value.id not in marked
                    and self.location(store.address) in slots
                ):
                    work.append(value)
                    changed = True
        return frozenset(marked)


_LOCATION_DEPTH = 8


def _addressing(function: Function) -> frozenset[int]:
    return _Addressing(function).solve()

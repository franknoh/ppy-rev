"""Acyclic branch regions whose paths can be executed separately and merged.

A branch whose successors all meet again at its immediate post-dominator, through blocks
that form no loop and make no calls, can be explored to that join and its states merged
into one: values that differ become if-then-else expressions over the path conditions.
Loops of such diamonds (a per-character transform, say) then cost one state per
iteration instead of one per combination of choices.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ppy_rev.analysis.locations import Location, Locations
from ppy_rev.ir.cfg import ControlFlow, control_flow, immediate_post_dominators
from ppy_rev.ir.model import (
    Branch,
    Call,
    DirectTarget,
    ExternalTarget,
    Function,
    Halt,
    IndirectJump,
    IndirectTarget,
    Jump,
    Load,
    Operand,
    Phi,
    Return,
    Store,
    TailCall,
    Var,
    operation_inputs,
    operation_output,
    successors,
    terminator_inputs,
)

MAX_REGION_BLOCKS = 32


@dataclass(frozen=True, slots=True)
class MergeRegion:
    branch: int
    join: int
    blocks: frozenset[int]
    """Blocks strictly between the branch and the join."""


class RegionFinder:
    def __init__(
        self,
        max_blocks: int = MAX_REGION_BLOCKS,
        helpers: Callable[[int], bool] | None = None,
    ) -> None:
        self.max_blocks = max_blocks
        self.helpers = helpers if helpers is not None else _no_helpers
        """Whether a call to this address may sit inside a region; by default none may."""
        self._post_dominators: dict[int, tuple[int | None, ...]] = {}
        self._flows: dict[int, ControlFlow] = {}
        self._regions: dict[tuple[int, int], MergeRegion | None] = {}
        self._addressing: dict[int, tuple[frozenset[int], frozenset[Location]]] = {}
        self._live: dict[int, tuple[frozenset[int], list[frozenset[int]]]] = {}

    def addressing(self, function: Function) -> frozenset[int]:
        """Values that flow into a memory address or a jump or call target.

        Merging paths that disagree on such a value would make those accesses symbolic.
        """
        return self._addressing_of(function)[0]

    def address_slots(self, function: Function) -> frozenset[Location]:
        """Memory locations whose contents are loaded and used as addresses."""
        return self._addressing_of(function)[1]

    def _addressing_of(self, function: Function) -> tuple[frozenset[int], frozenset[Location]]:
        known = self._addressing.get(function.entry)
        if known is None:
            known = _Addressing(function).solve()
            self._addressing[function.entry] = known
        return known

    def usable_after(self, function: Function, join: int) -> Callable[[int], bool]:
        """Whether a value may still be used from `join` on: whether it is live there.

        A frame also holds values from earlier trips round a loop. Those are dead at the
        join even when their block dominates it, as the block that makes a loop's counter
        can: any later use goes back through that block, which makes the value anew, and
        paths that disagree about the old one would otherwise never merge.
        """
        live = self._live.get(function.entry)
        if live is None:
            live = _live_at_entry(function)
            self._live[function.entry] = live
        defined, needed = live
        wanted = needed[join]

        def usable(identifier: int) -> bool:
            return identifier not in defined or identifier in wanted

        return usable

    def _callable(self, call: Call) -> bool:
        """Calls a region may contain: library output, and small helpers that always return.

        Everything the callee writes is merged with the rest of memory, and the values it
        computed are gone by the join, so what matters is only that both paths come back.
        """
        match call.target:
            case ExternalTarget():
                return True
            case DirectTarget(address=address):
                return self.helpers(address)
            case _:
                return False

    def region(self, function: Function, branch: int) -> MergeRegion | None:
        key = (function.entry, branch)
        if key not in self._regions:
            self._regions[key] = self._find(function, branch)
        return self._regions[key]

    def _flow(self, function: Function) -> ControlFlow:
        flow = self._flows.get(function.entry)
        if flow is None:
            flow = control_flow(function)
            self._flows[function.entry] = flow
        return flow

    def _find(self, function: Function, branch: int) -> MergeRegion | None:
        flow = self._flow(function)
        loop = _innermost_loop(flow, branch)
        live: set[int] | None = None
        if loop is None:
            post_dominators = self._post_dominators.get(function.entry)
            if post_dominators is None:
                post_dominators = immediate_post_dominators(function, _never_returns(function))
                self._post_dominators[function.entry] = post_dominators
            join = post_dominators[branch]
        else:
            header, body = loop
            live = _continuing(flow, header, body)
            join = _loop_join(flow, header, live, branch)
            returning = _returning(flow, branch)
            if any(
                target in returning and target not in live for target in flow.successors[branch]
            ):
                # A side leaves this loop and comes back round an enclosing one. clang -O2
                # splits a loop so, when a failed test must still call a helper that may
                # exit: meet where every way back meets, or each failure is a path of its own.
                live = returning
                join = _loop_join(flow, branch, returning, branch)
        if join is None:
            return None
        blocks: set[int] = set()
        work = list(successors(function.blocks[branch].terminator))
        while work:
            block_id = work.pop()
            if block_id == join or block_id in blocks:
                continue
            if live is not None and block_id not in live:
                continue  # the path leaves the loop: it escapes the region, unmerged
            if block_id == branch or len(blocks) >= self.max_blocks:
                return None
            block = function.blocks[block_id]
            # A `Halt` ends a path inside the region - a guard that calls `exit`. It never
            # arrives at the join, and the merge keeps only what arrives.
            if not isinstance(block.terminator, Jump | Branch | IndirectJump | Halt) or not all(
                self._callable(operation)
                for operation in block.operations
                if isinstance(operation, Call)
            ):
                return None
            blocks.add(block_id)
            work.extend(successors(block.terminator))
        if not _acyclic(function, blocks):
            return None
        return MergeRegion(branch, join, frozenset(blocks))


def _never_returns(function: Function) -> frozenset[int]:
    """Blocks from which the function cannot come back: they end the path, or loop forever."""
    returning = {
        block.id for block in function.blocks if isinstance(block.terminator, Return | TailCall)
    }
    work = list(returning)
    while work:
        block_id = work.pop()
        for predecessor in function.blocks:
            if block_id in successors(predecessor.terminator) and predecessor.id not in returning:
                returning.add(predecessor.id)
                work.append(predecessor.id)
    return frozenset(block.id for block in function.blocks if block.id not in returning)


def _innermost_loop(flow: ControlFlow, block: int) -> tuple[int, set[int]] | None:
    """The smallest natural loop containing `block`: all back edges to one header."""
    latches: dict[int, list[int]] = {}
    for source, targets in enumerate(flow.successors):
        for header in targets:
            if flow.dominates(header, source):
                latches.setdefault(header, []).append(source)
    best: tuple[int, set[int]] | None = None
    for header, sources in latches.items():
        body = {header}
        work = list(sources)
        while work:
            current = work.pop()
            if current not in body:
                body.add(current)
                work.extend(flow.predecessors[current])
        if block in body and (best is None or len(body) < len(best[1])):
            best = (header, body)
    return best


def _live_at_entry(function: Function) -> tuple[frozenset[int], list[frozenset[int]]]:
    """The values the function defines, and for each block those still used from its entry.

    A block's own phis count as live at its entry: they are assigned on the way in.
    """
    exposed: list[set[int]] = []
    made_in: list[set[int]] = []
    phi_uses: dict[tuple[int, int], set[int]] = {}
    for block in function.blocks:
        made = {phi.output.id for phi in block.phis}
        used: set[int] = set()
        for operation in block.operations:
            used.update(
                item.id
                for item in operation_inputs(operation)
                if isinstance(item, Var) and item.id not in made
            )
            made.update(item.id for item in operation_output(operation))
        used.update(
            item.id
            for item in terminator_inputs(block.terminator)
            if isinstance(item, Var) and item.id not in made
        )
        exposed.append(used)
        made_in.append(made)
        for phi in block.phis:
            for predecessor, operand in phi.incoming:
                if isinstance(operand, Var):
                    phi_uses.setdefault((predecessor, block.id), set()).add(operand.id)
    live = [set(item) for item in exposed]
    changed = True
    while changed:
        changed = False
        for block in reversed(function.blocks):
            leaving: set[int] = set()
            for target in successors(block.terminator):
                leaving |= live[target] | phi_uses.get((block.id, target), set())
            updated = exposed[block.id] | (leaving - made_in[block.id])
            if updated != live[block.id]:
                live[block.id] = updated
                changed = True
    defined = frozenset(identifier for made in made_in for identifier in made)
    return defined, [
        frozenset(live[block.id] | {phi.output.id for phi in block.phis})
        for block in function.blocks
    ]


def _returning(flow: ControlFlow, branch: int) -> set[int]:
    """Blocks on some way from `branch` round to `branch` again, and `branch` itself."""
    reaches: set[int] = set()
    work = list(flow.predecessors[branch])
    while work:
        current = work.pop()
        if current not in reaches:
            reaches.add(current)
            work.extend(flow.predecessors[current])
    reached = {branch}
    work = list(flow.successors[branch])
    while work:
        current = work.pop()
        if current not in reached:
            reached.add(current)
            work.extend(flow.successors[current])
    return (reaches & reached) | {branch}


def _continuing(flow: ControlFlow, header: int, body: set[int]) -> set[int]:
    """Blocks of the loop from which it can go round again (the others only leave it)."""
    live = {header}
    work = [source for source in flow.predecessors[header] if source in body]
    while work:
        current = work.pop()
        if current in live:
            continue
        live.add(current)
        work.extend(
            predecessor for predecessor in flow.predecessors[current] if predecessor in body
        )
    return live


def _loop_join(flow: ControlFlow, header: int, live: set[int], branch: int) -> int | None:
    """The nearest block every way round the loop from `branch` passes through.

    Paths that leave the loop are ignored; going back to the header counts as reaching the
    header itself.
    """
    if branch not in live:
        return None
    exit_node = -1
    nodes = sorted(live)

    def following(node: int) -> list[int]:
        return [
            exit_node if target == header else target
            for target in flow.successors[node]
            if target in live
        ]

    everything = frozenset([*nodes, exit_node])
    dominators: dict[int, frozenset[int]] = dict.fromkeys(nodes, everything)
    dominators[exit_node] = frozenset({exit_node})
    changed = True
    while changed:
        changed = False
        for node in nodes:
            targets = following(node)
            if not targets:
                continue
            meet = dominators[targets[0]]
            for target in targets[1:]:
                meet &= dominators[target]
            updated = meet | {node}
            if updated != dominators[node]:
                dominators[node] = updated
                changed = True
    candidates = dominators[branch] - {branch}
    if not candidates:
        return None
    nearest = max(candidates, key=lambda node: len(dominators[node]))
    return header if nearest == exit_node else nearest


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


class _Addressing:
    """Values that flow into memory addresses or jump targets, including through memory.

    A value stored where some address is later loaded from carries into that address;
    stores and loads are matched by location (see `ppy_rev.analysis.locations`).
    """

    def __init__(self, function: Function) -> None:
        self.locations = Locations(function)
        self.definitions = self.locations.definitions
        self.stores: list[Store] = []
        self.roots: list[Operand] = []
        for block in function.blocks:
            for operation in block.operations:
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

    def solve(self) -> tuple[frozenset[int], frozenset[Location]]:
        marked: set[int] = set()
        slots: set[Location] = set()
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
                        slots.add(self.locations.of(address))
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
                    and self.locations.of(store.address) in slots
                ):
                    work.append(value)
                    changed = True
        return frozenset(marked), frozenset(slots)


def _no_helpers(address: int) -> bool:
    del address
    return False


def mergeable_helper(
    function: Function,
    max_blocks: int = 24,
    lookup: Callable[[int], Function | None] | None = None,
    depth: int = 2,
) -> bool:
    """A small function that cannot loop: every path through it returns or stops.

    A path that stops - the range check that calls `exit` on a byte outside the printable
    range, a failed stack guard - never arrives at the join, and the merge keeps only the
    paths that did, so such a path costs the region nothing. What a helper may not do is
    run forever, which is why it may not loop and may only call helpers of its own.
    """
    if len(function.blocks) > max_blocks:
        return False
    flow = control_flow(function)
    if any(
        flow.dominates(target, source)
        for source, targets in enumerate(flow.successors)
        for target in targets
    ):
        return False
    if not all(
        isinstance(block.terminator, Jump | Branch | Return | Halt) for block in function.blocks
    ):
        return False
    return all(
        _helper_callable(operation, lookup, depth)
        for block in function.blocks
        for operation in block.operations
        if isinstance(operation, Call)
    )


def _helper_callable(
    call: Call, lookup: Callable[[int], Function | None] | None, depth: int
) -> bool:
    """Calls a helper may make: modelled externals, and smaller helpers of its own."""
    match call.target:
        case ExternalTarget():
            return True
        case DirectTarget(address=address):
            callee = None if lookup is None or depth <= 0 else lookup(address)
            return callee is not None and mergeable_helper(callee, lookup=lookup, depth=depth - 1)
        case _:
            return False

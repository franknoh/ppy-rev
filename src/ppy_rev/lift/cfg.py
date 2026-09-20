"""Control-flow recovery at p-code granularity.

Blocks are built from raw p-code, not from Ghidra's instruction-level block model, because
a single instruction can branch within its own p-code (for example `rep` prefixes and
flag updates of variable shifts). A program point is an (instruction address, p-code index)
pair; the point one past an instruction's last op is the next instruction's first point.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ppy_rev.ghidra.schema import Instruction, PcodeOp, Varnode


@dataclass(frozen=True, slots=True, order=True)
class Point:
    address: int
    index: int


@dataclass(frozen=True, slots=True)
class ProgramView:
    """What CFG recovery needs to know about the whole program."""

    instructions: dict[int, Instruction]
    function_entries: frozenset[int]
    no_return_targets: frozenset[int]


@dataclass(frozen=True, slots=True)
class FallThrough:
    target: Point


@dataclass(frozen=True, slots=True)
class Goto:
    target: Point
    op: PcodeOp


@dataclass(frozen=True, slots=True)
class CondGoto:
    condition: Varnode
    taken: Point
    not_taken: Point
    op: PcodeOp


@dataclass(frozen=True, slots=True)
class IndirectGoto:
    target: Varnode
    targets: tuple[Point, ...]
    op: PcodeOp


@dataclass(frozen=True, slots=True)
class ReturnExit:
    target: Varnode
    op: PcodeOp


@dataclass(frozen=True, slots=True)
class TailCallExit:
    """Control transfers to another function's entry without pushing a return address."""

    address: int


@dataclass(frozen=True, slots=True)
class HaltExit:
    """The block's last op is a call that never returns."""


@dataclass(frozen=True, slots=True)
class StopExit:
    reason: str


type Exit = (
    FallThrough | Goto | CondGoto | IndirectGoto | ReturnExit | TailCallExit | HaltExit | StopExit
)


@dataclass(slots=True)
class PcodeBlock:
    id: int
    start: Point
    ops: list[tuple[Point, PcodeOp]] = field(default_factory=list[tuple[Point, PcodeOp]])
    exit: Exit = field(default_factory=lambda: StopExit("unterminated block"))
    predecessors: list[int] = field(default_factory=list[int])

    @property
    def address(self) -> int:
        return self.start.address


@dataclass(frozen=True, slots=True)
class FunctionCfg:
    entry: int
    blocks: tuple[PcodeBlock, ...]
    """Block 0 is the entry. Successor points resolve through `block_at`."""
    block_at: dict[Point, int]

    def successors(self, block: PcodeBlock) -> tuple[int, ...]:
        targets: list[Point] = []
        match block.exit:
            case FallThrough(target=target) | Goto(target=target):
                targets.append(target)
            case CondGoto(taken=taken, not_taken=not_taken):
                targets.extend((taken, not_taken))
            case IndirectGoto(targets=indirect):
                targets.extend(indirect)
            case ReturnExit() | TailCallExit() | HaltExit() | StopExit():
                pass
        ordered: list[int] = []
        for target in targets:
            block_id = self.block_at[target]
            if block_id not in ordered:
                ordered.append(block_id)
        return tuple(ordered)


class _Recovery:
    def __init__(self, program: ProgramView, entry: int) -> None:
        self.program = program
        self.entry = entry

    def canonical(self, point: Point) -> Point:
        """Normalize a point past the end of an instruction onto the next instruction."""
        while True:
            instruction = self.program.instructions.get(point.address)
            if instruction is None or point.index < len(instruction.pcode):
                return point
            point = Point(
                instruction.address + instruction.length, point.index - len(instruction.pcode)
            )

    def next_point(self, point: Point) -> Point:
        return self.canonical(Point(point.address, point.index + 1))

    def is_foreign_entry(self, address: int) -> bool:
        return address != self.entry and address in self.program.function_entries

    def branch_target(self, point: Point, target: Varnode) -> Point:
        if target.space == "const":
            # p-code relative branch: offset (signed, in the varnode's size) within the
            # instruction's op list.
            bits = target.size * 8
            relative = target.offset - (1 << bits) if target.offset >> (bits - 1) else target.offset
            return self.canonical(Point(point.address, point.index + relative))
        return self.canonical(Point(target.offset, 0))

    def op_at(self, point: Point) -> PcodeOp | None:
        instruction = self.program.instructions.get(point.address)
        if instruction is None or not 0 <= point.index < len(instruction.pcode):
            return None
        return instruction.pcode[point.index]

    def edges(self, point: Point, op: PcodeOp) -> tuple[Exit | None, tuple[Point, ...]]:
        """Classify an op: (exit when it ends a block, intraprocedural successor points)."""
        match op.opcode:
            case "BRANCH":
                target = op.inputs[0]
                if target.space != "const" and self.is_foreign_entry(target.offset):
                    return TailCallExit(target.offset), ()
                destination = self.branch_target(point, target)
                return Goto(destination, op), (destination,)
            case "CBRANCH":
                taken = self._conditional_target(point, op.inputs[0])
                not_taken = self.next_point(point)
                return CondGoto(op.inputs[1], taken, not_taken, op), (taken, not_taken)
            case "BRANCHIND":
                instruction = self.program.instructions[point.address]
                targets = tuple(self._jump_target(flow) for flow in instruction.flows)
                return IndirectGoto(op.inputs[0], targets, op), targets
            case "RETURN":
                return ReturnExit(op.inputs[0], op), ()
            case "CALL" if (
                op.inputs[0].space != "const"
                and op.inputs[0].offset in self.program.no_return_targets
            ):
                return HaltExit(), ()
            case _:
                return None, (self.next_point(point),)

    def _conditional_target(self, point: Point, target: Varnode) -> Point:
        if target.space == "const":
            return self.branch_target(point, target)
        return self._jump_target(target.offset)

    def _jump_target(self, address: int) -> Point:
        if self.is_foreign_entry(address):
            # Control leaves for another function: route through a synthetic block whose
            # only content is the tail call. Index -1 never names a real p-code op.
            return Point(address, -1)
        return self.canonical(Point(address, 0))

    def recover(self) -> FunctionCfg:
        start = self.canonical(Point(self.entry, 0))
        leaders: set[Point] = {start}
        seen: set[Point] = set()
        work = [start]
        branch_targets: set[Point] = set()
        while work:
            point = work.pop()
            if point in seen:
                continue
            seen.add(point)
            op = self.op_at(point)
            if op is None:
                continue
            exit_, successors = self.edges(point, op)
            if exit_ is not None:
                leaders.update(successors)
                branch_targets.update(successors)
            work.extend(successors)
        return self._blocks(start, leaders, branch_targets)

    def _blocks(self, start: Point, leaders: set[Point], branch_targets: set[Point]) -> FunctionCfg:
        blocks: list[PcodeBlock] = []
        if start in branch_targets:
            # Block 0 must have no predecessors: function inputs are defined before it.
            blocks.append(PcodeBlock(id=0, start=start, exit=FallThrough(start)))
        preheader_count = len(blocks)
        block_at: dict[Point, int] = {}
        for point in [start, *sorted(leaders - {start})]:
            block_at[point] = len(blocks)
            blocks.append(PcodeBlock(id=len(blocks), start=point))
        for block in blocks[preheader_count:]:
            self._fill(block, leaders)
        cfg = FunctionCfg(entry=self.entry, blocks=tuple(blocks), block_at=block_at)
        for block in blocks:
            for successor in cfg.successors(block):
                blocks[successor].predecessors.append(block.id)
        if not preheader_count and blocks[0].predecessors:
            # The code before the entry falls into it, so the entry is inside a loop. It
            # needs the same preheader a branch back to it would have earned: without one,
            # a value carried around that loop has nowhere to come from on the way in.
            return self._blocks(start, leaders, branch_targets | {start})
        return cfg

    def _fill(self, block: PcodeBlock, leaders: set[Point]) -> None:
        if block.start.index == -1:
            block.exit = TailCallExit(block.start.address)
            return
        point = block.start
        while True:
            op = self.op_at(point)
            if op is None:
                block.exit = StopExit(f"no instruction at {point.address:#x}")
                return
            block.ops.append((point, op))
            exit_, successors = self.edges(point, op)
            if exit_ is not None:
                block.exit = exit_
                return
            (following,) = successors
            if following in leaders:
                block.exit = FallThrough(following)
                return
            point = following


def recover_cfg(program: ProgramView, entry: int) -> FunctionCfg:
    return _Recovery(program, entry).recover()

from __future__ import annotations

from ppy_rev.ir.cfg import immediate_post_dominators
from ppy_rev.ir.model import (
    BinaryOpcode,
    Branch,
    Call,
    Const,
    DirectTarget,
    Function,
    Jump,
    Return,
    Terminator,
)
from ppy_rev.symbolic.regions import MergeRegion, RegionFinder
from support.revir import ORIGIN, FunctionBuilder


def _function(edges: dict[int, tuple[int, ...]], calls: frozenset[int] = frozenset()) -> Function:
    """Blocks 0..n-1 with the given successors: two targets branch, one jumps, none return."""
    builder = FunctionBuilder([("RDI", 64)])
    condition = builder.input("RDI")
    for block_id in range(len(edges)):
        block = builder.block()
        if block_id in calls:
            block.operations.append(Call(DirectTarget(0x2000), (), (), (), (), ORIGIN))
        terminator: Terminator
        match edges[block_id]:
            case (true_target, false_target):
                terminator = Branch(condition, true_target, false_target, ORIGIN)
            case (target,):
                terminator = Jump(target, ORIGIN)
            case _:
                terminator = Return((Const(0, 64),), None, ORIGIN)
        builder.terminators[block_id] = terminator
    return builder.finish(("RAX",))


DIAMOND = {0: (1, 2), 1: (3,), 2: (1, 3), 3: ()}
LOOP = {0: (1,), 1: (2, 3), 2: (1,), 3: ()}
EARLY_RETURN = {0: (1, 2), 1: (), 2: (3,), 3: ()}


def test_post_dominators() -> None:
    assert immediate_post_dominators(_function(DIAMOND)) == (3, 3, 3, None)
    assert immediate_post_dominators(_function(LOOP)) == (1, 3, 1, None)
    assert immediate_post_dominators(_function(EARLY_RETURN)) == (None, None, 3, None)


def test_regions_are_loop_free_call_free_diamonds() -> None:
    finder = RegionFinder()
    assert finder.region(_function(DIAMOND), 0) == MergeRegion(0, 3, frozenset({1, 2}))
    assert finder.region(_function(LOOP), 1) is None
    assert RegionFinder().region(_function(EARLY_RETURN), 0) is None
    assert RegionFinder().region(_function(DIAMOND, calls=frozenset({2})), 0) is None
    assert RegionFinder(max_blocks=1).region(_function(DIAMOND), 0) is None


def test_addressing_follows_values_through_memory() -> None:
    builder = FunctionBuilder([("RDI", 64), ("RSI", 64)])
    block = builder.block()
    pointer = block.binary(BinaryOpcode.ADD, builder.input("RDI"), Const(1, 64))
    data = block.binary(BinaryOpcode.ADD, builder.input("RSI"), Const(2, 64))
    block.store(Const(0x5000, 64), pointer)  # a pointer kept in a slot
    block.store(Const(0x6000, 64), data)  # plain data
    reloaded = block.load(Const(0x5000, 64), 64)
    block.load(reloaded, 8)
    block.load(Const(0x6000, 64), 64)
    builder.terminators[block.id] = Return((), None, ORIGIN)
    addressing = RegionFinder().addressing(builder.finish(()))
    assert pointer.id in addressing and builder.input("RDI").id in addressing
    assert data.id not in addressing and builder.input("RSI").id not in addressing

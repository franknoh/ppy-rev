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
from ppy_rev.symbolic.regions import MergeRegion, RegionFinder, mergeable_helper
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


LOOP_WITH_EXIT_ARM = {0: (1,), 1: (2, 6), 2: (3, 4), 3: (5,), 4: (5, 7), 5: (1,), 6: (), 7: ()}
"""A loop whose diamond has an arm that may leave the function (block 7)."""


def test_loop_diamonds_merge_where_the_paths_that_stay_meet() -> None:
    finder = RegionFinder()
    function = _function(LOOP_WITH_EXIT_ARM)
    assert finder.region(function, 2) == MergeRegion(2, 5, frozenset({3, 4}))
    assert finder.region(function, 4) == MergeRegion(4, 5, frozenset())
    # A branch whose ways round the loop meet only at the header merges there.
    rotated = _function({0: (1,), 1: (2, 3), 2: (1, 4), 3: (1,), 4: ()})
    assert RegionFinder().region(rotated, 1) == MergeRegion(1, 1, frozenset({2, 3}))


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


def test_only_helpers_that_always_return_are_mergeable() -> None:
    assert mergeable_helper(_function(DIAMOND))
    assert not mergeable_helper(_function(LOOP))  # might not reach the join
    assert not mergeable_helper(_function(DIAMOND, calls=frozenset({2})))  # may call anything
    assert not mergeable_helper(_function(DIAMOND), max_blocks=2)


def test_a_small_leaf_helper_may_sit_inside_a_region() -> None:
    """Per-character loops often call a tiny helper; refusing those loses every merge."""
    calling = _function(DIAMOND, calls=frozenset({2}))
    assert RegionFinder().region(calling, 0) is None
    allowed = RegionFinder(helpers=lambda address: True)
    assert allowed.region(calling, 0) == MergeRegion(0, 3, frozenset({1, 2}))

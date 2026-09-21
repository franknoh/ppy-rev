from __future__ import annotations

from ppy_rev.ir.cfg import immediate_post_dominators
from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Block,
    Branch,
    Call,
    Const,
    DirectTarget,
    ExternalTarget,
    Function,
    FunctionInput,
    Halt,
    Jump,
    Phi,
    Return,
    Terminator,
    Var,
)
from ppy_rev.symbolic.regions import MergeRegion, RegionFinder, mergeable_helper
from support.revir import ORIGIN, FunctionBuilder


def _function(
    edges: dict[int, tuple[int, ...]],
    calls: frozenset[int] = frozenset(),
    halts: frozenset[int] = frozenset(),
) -> Function:
    """Blocks 0..n-1 with the given successors: two targets branch, one jumps, none return.

    A block in `halts` ends the path instead, the way a call to `exit` does.
    """
    builder = FunctionBuilder([("RDI", 64)])
    condition = builder.input("RDI")
    for block_id in range(len(edges)):
        block = builder.block()
        if block_id in calls:
            block.operations.append(Call(DirectTarget(0x2000), (), (), (), (), ORIGIN))
        terminator: Terminator
        if block_id in halts:
            block.operations.append(Call(ExternalTarget("exit", 0x3000), (), (), (), (), ORIGIN))
            builder.terminators[block_id] = Halt(ORIGIN)
            continue
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


GUARDED = {0: (1, 2), 1: (3, 2), 2: (), 3: ()}
"""`if (c < 0x20 || c == 0x7f) exit(1);` before the work: block 2 never comes back."""


def test_a_side_that_never_comes_back_does_not_hide_the_join() -> None:
    """Every path that carries on goes through block 1, whatever the guard does."""
    function = _function(GUARDED, halts=frozenset({2}))
    assert immediate_post_dominators(function) == (None, None, None, None)
    assert immediate_post_dominators(function, ignore=frozenset({2})) == (1, 3, None, None)


def test_a_guard_that_exits_sits_inside_a_region() -> None:
    finder = RegionFinder()
    function = _function(GUARDED, halts=frozenset({2}))
    assert finder.region(function, 0) == MergeRegion(0, 1, frozenset({2}))
    assert finder.region(function, 1) == MergeRegion(1, 3, frozenset({2}))


def test_a_helper_may_give_up_on_input_it_refuses() -> None:
    """A per-character helper that rejects bytes out of range still merges around it."""
    function = _function(GUARDED, halts=frozenset({2}))
    assert mergeable_helper(function)
    assert not mergeable_helper(_function(LOOP))  # might never come back at all


def test_a_helper_may_call_another_helper_but_not_far() -> None:
    leaf = _function(DIAMOND)
    caller = _function(DIAMOND, calls=frozenset({2}))
    assert not mergeable_helper(caller)  # nothing says what it calls
    assert mergeable_helper(caller, lookup={0x2000: leaf}.get)
    assert not mergeable_helper(caller, lookup={0x2000: caller}.get, depth=0)


SPLIT_LOOP = {0: (2,), 1: (5, 2), 2: (3,), 3: (1, 4), 4: (1, 6), 5: (), 6: (3, 7), 7: ()}
"""clang -O2's loop of two tests that must keep calling a helper after one fails.

Block 3 is the first test, 4 the second, 6 the latch of the loop that runs while every
test passed; a failure goes through 1, which may leave (5), and 2 back into that loop.
"""


def test_a_failure_that_comes_back_round_an_enclosing_loop_is_merged() -> None:
    """Both ways from the first test come back to it, so that is where they meet."""
    region = RegionFinder().region(_function(SPLIT_LOOP), 3)
    assert region == MergeRegion(3, 3, frozenset({1, 2, 4, 6}))


def test_values_from_an_earlier_trip_round_a_loop_do_not_stop_a_merge() -> None:
    """Only what is live at the join has to agree, not all that the join's dominators made.

    Block 1 makes the loop's counter from `old`, which nothing past block 1 reads. Two paths
    arriving at block 2, one having come through block 1 more recently, disagree about
    `old`; had that counted, clang's split loop would never merge at all.
    """
    condition, old, counter = Var(1, 64), Var(2, 64), Var(3, 64)
    blocks = (
        Block(0, 0x1000, (), (), Jump(1, ORIGIN)),
        Block(
            1,
            0x1000,
            (Phi(old, ((0, Const(0, 64)), (2, counter))),),
            (BinaryOp(BinaryOpcode.ADD, counter, old, Const(1, 64), ORIGIN),),
            Jump(2, ORIGIN),
        ),
        Block(2, 0x1000, (), (), Branch(condition, 1, 3, ORIGIN)),
        Block(3, 0x1000, (), (), Return((counter,), None, ORIGIN)),
    )
    function = Function("f", 0x1000, (FunctionInput("RDI", condition),), ("RAX",), blocks)
    usable = RegionFinder().usable_after(function, 2)
    assert usable(counter.id)  # read again on the way round and on the way out
    assert not usable(old.id)  # block 1 dominates the join, but `old` is dead there
    assert usable(condition.id)  # not defined here at all: kept, whatever it is

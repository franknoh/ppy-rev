from __future__ import annotations

from ppy_rev.ir.cfg import immediate_post_dominators
from ppy_rev.ir.model import (
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

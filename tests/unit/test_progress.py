from __future__ import annotations

import io
import time

from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.progress import Periodic, Silent, count, plural, reporter
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.executor import Executor, Goal
from ppy_rev.symbolic.harness import call_state
from support.exports import ProgramBuilder, const, op, ram, reg, ret


def test_a_quick_phase_stays_silent() -> None:
    stream = io.StringIO()
    Periodic(stream, after=10.0).report("symbolic search", "8 paths waiting")
    assert stream.getvalue() == ""


def test_a_slow_phase_reports_once_per_interval() -> None:
    stream = io.StringIO()
    progress = Periodic(stream, after=10.0, every=5.0, started=time.monotonic() - 20.0)
    progress.report("symbolic search", "8 paths waiting")
    progress.report("symbolic search", "9 paths waiting")  # too soon after the first
    assert stream.getvalue().count("\n") == 1
    line = stream.getvalue()
    assert line.startswith("[ppy-rev 20s] symbolic search: 8 paths waiting")


def test_reporting_is_off_for_a_stream_that_is_not_a_terminal() -> None:
    assert isinstance(reporter(io.StringIO()), Silent)
    assert isinstance(reporter(io.StringIO(), enabled=True), Periodic)
    assert isinstance(reporter(io.StringIO(), enabled=False), Silent)


def test_counts_are_short_and_plurals_agree() -> None:
    assert [count(9), count(12_345), count(4_100_000)] == ["9", "12.3k", "4.1M"]
    assert [plural(1, "path"), plural(2, "path")] == ["1 path", "2 paths"]


def _counting_module(limit: int) -> Module:
    """`f`: a concrete loop long enough for the executor to report from inside one path."""
    program = ProgramBuilder()
    loop = program.code(0x1000, [op("COPY", [const(0, 8)], reg("RAX"))])
    program.code(
        loop,
        [
            op("INT_ADD", [reg("RAX"), const(1, 8)], reg("RAX")),
            op("INT_NOTEQUAL", [reg("RAX"), const(limit, 8)], reg("ZF")),
            op("CBRANCH", [ram(loop), reg("ZF")]),
        ],
    )
    program.code(loop + 4, ret(), length=1)
    program.function("f", 0x1000)
    return simplify_module(lift_export(program.build()).module)


def test_a_long_running_path_reports_while_it_runs() -> None:
    limit = 100_000
    module = _counting_module(limit)
    function = module.function_named("f")
    assert function is not None
    stream = io.StringIO()
    executor = Executor(
        module,
        Z3Backend(),
        Goal(on_return=lambda outputs: sx.equal(outputs["RAX"], sx.const(limit, 64))),
        progress=Periodic(stream, after=0.0, every=0.0, started=time.monotonic() - 1.0),
    )
    exploration = executor.explore(call_state(executor, module, function, {}))
    assert exploration.reached
    lines = stream.getvalue().splitlines()
    assert lines and all(line.startswith("[ppy-rev ") for line in lines)
    # The first line comes from the search loop before anything ran; a later one can only
    # come from the hook inside a single long-running path.
    assert any("0 operations" not in line for line in lines), lines

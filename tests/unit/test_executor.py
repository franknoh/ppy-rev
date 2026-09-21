from __future__ import annotations

from dataclasses import replace

from ppy_rev.diagnostics import DiagnosticCode
from ppy_rev.execution.interpreter import Interpreter
from ppy_rev.execution.process import enter_call, standard_memory
from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.solver.backend import CheckResult, Status
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.concolic import concolic_search
from ppy_rev.symbolic.executor import Budget, Executor, Goal, StopReason
from ppy_rev.symbolic.harness import FunctionSolution, call_state, solve_function
from support.exports import ProgramBuilder, call, const, op, ram, reg, ret


def _module(program: ProgramBuilder, simplify: bool = True) -> Module:
    module = lift_export(program.build()).module
    return simplify_module(module) if simplify else module


def _rax_is(value: int) -> Goal:
    return Goal(on_return=lambda outputs: sx.equal(outputs["RAX"], sx.const(value, 64)))


def _solve(module: Module, goal: Goal, budget: Budget | None = None) -> FunctionSolution:
    function = module.function_named("f")
    assert function is not None
    return solve_function(
        module, function, {"RDI": sx.symbol("x", 64)}, goal, Z3Backend(), budget=budget
    )


def _interpret(module: Module, x: int) -> int:
    function = module.function_named("f")
    assert function is not None
    memory = standard_memory(module)
    frame = enter_call(module, memory, {"RDI": x})
    return Interpreter(module, memory).call(function, frame.registers, frame.return_address)["RAX"]


def _xor_check(program: ProgramBuilder, entry: int = 0x1000) -> int:
    """if ((rdi ^ 0x41) == 0x12) rax = 1 (at entry+8) else rax = 0; ret (at entry+12)"""
    after = program.code(
        entry,
        [
            op("INT_XOR", [reg("RDI"), const(0x41, 8)], reg("RCX")),
            op("INT_EQUAL", [reg("RCX"), const(0x12, 8)], reg("ZF")),
            op("COPY", [const(0, 8)], reg("RAX")),
            op("CBRANCH", [ram(entry + 8), reg("ZF")]),
        ],
    )
    done = program.code(after, [op("BRANCH", [ram(entry + 12)])])
    exit_ = program.code(done, [op("COPY", [const(1, 8)], reg("RAX"))])
    return program.code(exit_, ret(), length=1)


def test_branch_condition_is_solved_and_verified() -> None:
    program = ProgramBuilder()
    _xor_check(program)
    program.function("f", 0x1000)
    for simplify in (False, True):
        module = _module(program, simplify)
        model = _solve(module, _rax_is(1)).model
        assert model == {"x": 0x53}
        assert _interpret(module, 0x53) == 1


def test_unreachable_goal_explores_everything_without_a_solution() -> None:
    program = ProgramBuilder()
    _xor_check(program)
    program.function("f", 0x1000)
    solution = _solve(_module(program), _rax_is(7))
    assert solution.model is None
    assert solution.exploration.incomplete == []
    # Both sides of the branch meet again before returning, as one merged state.
    assert solution.exploration.statistics.stops[StopReason.RETURNED] == 1
    assert solution.exploration.statistics.merges == 1


def test_goal_and_avoid_addresses() -> None:
    program = ProgramBuilder()
    _xor_check(program)
    program.function("f", 0x1000)
    module = _module(program)
    reached = _solve(module, Goal(addresses=frozenset({0x1008})))
    assert reached.model == {"x": 0x53}
    avoided = _solve(module, Goal(addresses=frozenset({0x1008}), avoid=frozenset({0x1008})))
    assert avoided.model is None
    assert avoided.exploration.statistics.stops[StopReason.AVOIDED] == 1


def test_unsupported_semantics_on_the_path_are_reported() -> None:
    program = ProgramBuilder()
    after = program.code(0x1000, [op("CALLOTHER", [const(3, 4)], None, user_op="cpuid")])
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    solution = _solve(_module(program), _rax_is(0))
    assert solution.model is None
    (stop,) = solution.exploration.incomplete
    assert stop.reason is StopReason.UNSUPPORTED
    assert stop.code is DiagnosticCode.UNSUPPORTED_USER_OP


def test_symbolic_divisor_must_be_nonzero() -> None:
    program = ProgramBuilder()
    after = program.code(
        0x1000,
        [
            op("COPY", [const(100, 8)], reg("RAX")),
            op("INT_DIV", [reg("RAX"), reg("RDI")], reg("RAX")),
        ],
    )
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    solution = _solve(_module(program), _rax_is(0xFFFFFFFFFFFFFFFF))
    assert solution.model is None  # SMT would allow 100 / 0 == ~0; RevIR faults instead
    exact = _solve(_module(program), _rax_is(50))
    assert exact.model == {"x": 2}


def test_symbolic_loop_is_bounded() -> None:
    program = ProgramBuilder()
    loop = program.code(0x1000, [op("COPY", [const(0, 8)], reg("RAX"))])
    program.code(
        loop,
        [
            op("INT_ADD", [reg("RAX"), const(1, 8)], reg("RAX")),
            op("INT_NOTEQUAL", [reg("RAX"), reg("RDI")], reg("ZF")),
            op("CBRANCH", [ram(loop), reg("ZF")]),
        ],
    )
    program.code(loop + 4, ret(), length=1)
    program.function("f", 0x1000)
    module = _module(program)
    bounded = _solve(module, _rax_is(1000), Budget(max_branch_visits=20))
    assert bounded.model is None
    assert any(stop.reason is StopReason.BRANCH_BOUND for stop in bounded.exploration.incomplete)
    found = _solve(module, _rax_is(5), Budget(max_branch_visits=20))
    assert found.model == {"x": 5}


def test_wide_symbolic_pointers_are_unsupported_not_guessed() -> None:
    program = ProgramBuilder()
    after = program.code(0x1000, [op("LOAD", [reg("RDI")], reg("RAX"))])
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    solution = _solve(_module(program), _rax_is(1))
    (stop,) = solution.exploration.incomplete
    assert stop.code is DiagnosticCode.SYMBOLIC_POINTER_REQUIRED


def test_reading_an_imported_object_is_unsupported_not_a_crash() -> None:
    """Ghidra gives `std::cin` an address no section holds, and optimized C++ reads it.

    Reading there faults, but the program is not the one at fault: no model put anything
    in that object. Treating the path as dead would let a whole search end in `unsat`.
    """
    program = ProgramBuilder()
    program.symbol("cin", 0x500000)
    after = program.code(0x1000, [op("LOAD", [const(0x500000, 8)], reg("RAX"))])
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    solution = _solve(_module(program), _rax_is(1))
    assert solution.model is None
    (stop,) = solution.exploration.incomplete
    assert stop.reason is StopReason.UNSUPPORTED
    assert stop.detail == "no model for the library object cin"


def test_a_pointer_chosen_between_constants_is_read_without_the_solver() -> None:
    """What `strchr` returns: one address per position, or NULL — far apart, but few."""
    from ppy_rev.symbolic.executor import constant_choices

    condition = sx.bool_not(sx.equal(sx.symbol("x", 8), sx.const(0, 8)))
    chosen = sx.ite(condition, sx.const(0x7FFF_0000, 64), sx.const(0, 64))
    assert constant_choices(chosen, 64) == [0, 0x7FFF_0000]
    assert constant_choices(chosen, 1) is None
    assert constant_choices(sx.symbol("p", 64), 64) is None


def test_small_symbolic_pointer_reads_a_table() -> None:
    program = ProgramBuilder()
    program.data(".rodata", 0x3000, bytes(range(0x40, 0x60)))
    after = program.code(
        0x1000,
        [
            op("INT_AND", [reg("RDI"), const(0x1F, 8)], reg("RCX")),
            op("INT_ADD", [reg("RCX"), const(0x3000, 8)], reg("RCX")),
            op("LOAD", [reg("RCX")], reg("AL")),
            op("INT_ZEXT", [reg("AL")], reg("RAX")),
        ],
    )
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    module = _module(program)
    solution = _solve(module, _rax_is(0x5A))
    assert solution.model is not None
    assert _interpret(module, solution.model["x"]) == 0x5A


def test_calls_into_lifted_helpers() -> None:
    program = ProgramBuilder()
    _xor_check(program, entry=0x2000)
    program.function("helper", 0x2000)
    after = program.code(0x1000, call(0x2000, 0x1004))
    program.code(after, [op("INT_MULT", [reg("RAX"), const(7, 8)], reg("RAX")), *ret()])
    program.function("f", 0x1000)
    module = _module(program)
    solution = _solve(module, _rax_is(7))
    assert solution.model == {"x": 0x53}


def test_symbolic_pointer_is_bounded_by_the_path_condition() -> None:
    # if (x < 8) rax = table[x]; a jump table's shape: the index is only bounded by a branch.
    program = ProgramBuilder()
    program.data(
        ".rodata", 0x3000, b"".join((index * 0x11).to_bytes(4, "little") for index in range(8))
    )
    lookup = program.code(
        0x1000,
        [
            op("COPY", [const(0, 8)], reg("RAX")),
            op("INT_LESS", [reg("RDI"), const(8, 8)], reg("CF")),
            op("BOOL_NEGATE", [reg("CF")], reg("ZF")),
            op("CBRANCH", [ram(0x100C), reg("ZF")]),
        ],
    )
    done = program.code(
        lookup,
        [
            op("INT_MULT", [reg("RDI"), const(4, 8)], reg("RCX")),
            op("INT_ADD", [reg("RCX"), const(0x3000, 8)], reg("RCX")),
            op("LOAD", [reg("RCX")], reg("EAX")),
            op("INT_ZEXT", [reg("EAX")], reg("RAX")),
        ],
    )
    program.code(done, [op("BRANCH", [ram(0x100C)])])
    program.code(0x100C, ret(), length=1)
    program.function("f", 0x1000)
    module = _module(program)
    solution = _solve(module, _rax_is(0x55))
    assert solution.model == {"x": 5}
    assert solution.exploration.incomplete == []


def test_a_pointer_with_one_value_is_found_without_bounding_it() -> None:
    """x == 0x3004 makes the load address certain: asking for its values settles it."""
    program = ProgramBuilder()
    program.data(
        ".rodata", 0x3000, b"".join((index * 0x11).to_bytes(4, "little") for index in range(8))
    )
    body = program.code(
        0x1000,
        [
            op("COPY", [const(0, 8)], reg("RAX")),
            op("INT_NOTEQUAL", [reg("RDI"), const(0x3004, 8)], reg("ZF")),
            op("CBRANCH", [ram(0x1008), reg("ZF")]),
        ],
    )
    program.code(
        body, [op("LOAD", [reg("RDI")], reg("EAX")), op("INT_ZEXT", [reg("EAX")], reg("RAX"))]
    )
    program.code(0x1008, ret(), length=1)
    program.function("f", 0x1000)
    module = _module(program)
    executor = Executor(module, Z3Backend(), _rax_is(0x11))
    function = module.function_named("f")
    assert function is not None
    state = call_state(executor, module, function, {"RDI": sx.symbol("x", 64)})
    exploration = executor.explore(state)
    assert exploration.reached
    assert executor.statistics.solver_calls < 16


def _bit_sum_loop() -> Module:
    """rax = sum of i for every set bit i < 16 of rdi, with one branch per bit."""
    program = ProgramBuilder()
    loop = program.code(
        0x1000, [op("COPY", [const(0, 8)], reg("RAX")), op("COPY", [const(0, 8)], reg("RCX"))]
    )
    take = program.code(
        loop,
        [
            op("INT_RIGHT", [reg("RDI"), reg("CL")], reg("RDX")),
            op("INT_AND", [reg("RDX"), const(1, 8)], reg("RDX")),
            op("INT_EQUAL", [reg("RDX"), const(0, 8)], reg("ZF")),
            op("CBRANCH", [ram(loop + 8), reg("ZF")]),
        ],
    )
    step = program.code(take, [op("INT_ADD", [reg("RAX"), reg("RCX")], reg("RAX"))])
    exit_ = program.code(
        step,
        [
            op("INT_ADD", [reg("RCX"), const(1, 8)], reg("RCX")),
            op("INT_LESS", [reg("RCX"), const(16, 8)], reg("CF")),
            op("CBRANCH", [ram(loop), reg("CF")]),
        ],
    )
    program.code(exit_, ret(), length=1)
    program.function("f", 0x1000)
    return _module(program)


def test_branch_diamonds_in_a_loop_are_merged() -> None:
    module = _bit_sum_loop()
    budget = Budget(max_states=200)
    merged = _solve(module, _rax_is(1 + 4 + 15), budget)
    assert merged.model is not None
    assert _interpret(module, merged.model["x"]) == 20
    assert merged.exploration.statistics.merges == 16
    separate = _solve(module, _rax_is(1 + 4 + 15), replace(budget, merge_paths=False))
    assert separate.model is None
    assert separate.exploration.budget_exhausted is not None


def test_paths_disagreeing_on_a_concrete_address_are_not_merged() -> None:
    # rcx = (rdi == 0x41) ? 1 : 2; rax = table[rcx]: merging would make the load symbolic.
    program = ProgramBuilder()
    program.data(".rodata", 0x3000, bytes([0x10, 0x20, 0x30]))
    after = program.code(
        0x1000,
        [
            op("COPY", [const(1, 8)], reg("RCX")),
            op("INT_EQUAL", [reg("RDI"), const(0x41, 8)], reg("ZF")),
            op("CBRANCH", [ram(0x1008), reg("ZF")]),
        ],
    )
    after = program.code(after, [op("COPY", [const(2, 8)], reg("RCX"))])
    after = program.code(
        after,
        [
            op("INT_ADD", [reg("RCX"), const(0x3000, 8)], reg("RCX")),
            op("LOAD", [reg("RCX")], reg("AL")),
            op("INT_ZEXT", [reg("AL")], reg("RAX")),
        ],
    )
    program.code(after, ret(), length=1)
    program.function("f", 0x1000)
    solution = _solve(_module(program), _rax_is(0x20))
    assert solution.model == {"x": 0x41}
    statistics = solution.exploration.statistics
    assert statistics.merges == 0
    assert statistics.stops[StopReason.GOAL] == 1


def test_seeded_run_follows_the_seed_and_records_flips() -> None:
    program = ProgramBuilder()
    _xor_check(program)
    program.function("f", 0x1000)
    module = _module(program, simplify=False)
    function = module.function_named("f")
    assert function is not None
    x = sx.symbol("x", 64)
    seeded = Executor(module, Z3Backend(), _rax_is(1))
    seeded.seed = {"x": 0}
    exploration = seeded.explore(call_state(seeded, module, function, {"RDI": x}))
    assert exploration.reached == []
    assert exploration.statistics.stops[StopReason.RETURNED] == 1
    (flip,) = seeded.flips
    assert seeded.solve_conditions(flip.conditions, [x]) == {"x": 0x53}


def test_concolic_search_flips_its_way_to_the_goal() -> None:
    program = ProgramBuilder()
    _xor_check(program)
    program.function("f", 0x1000)
    module = _module(program)
    function = module.function_named("f")
    assert function is not None
    x = sx.symbol("x", 64)
    search = Executor(module, Z3Backend(), _rax_is(1))
    result = concolic_search(
        search,
        lambda: call_state(search, module, function, {"RDI": x}),
        [x],
        {"x": 0},
        None,
        max_runs=8,
        max_seconds=30,
    )
    assert (result.runs, result.flips) == (2, 1)
    (reached,) = result.exploration.reached
    assert search.solve(reached.state, [x]) == {"x": 0x53}


def _nested_equality(inner: int) -> Module:
    """`rax = 0; if (x == 5) { if (x == inner) rax = 1 /* 0x1010 */; } return rax;`"""
    program = ProgramBuilder()
    program.code(
        0x1000,
        [
            op("INT_EQUAL", [reg("RDI"), const(5, 8)], reg("ZF")),
            op("COPY", [const(0, 8)], reg("RAX")),
            op("CBRANCH", [ram(0x1008), reg("ZF")]),
        ],
    )
    program.code(0x1004, [op("BRANCH", [ram(0x1014)])])
    program.code(
        0x1008,
        [
            op("INT_EQUAL", [reg("RDI"), const(inner, 8)], reg("ZF")),
            op("CBRANCH", [ram(0x1010), reg("ZF")]),
        ],
    )
    program.code(0x100C, [op("BRANCH", [ram(0x1014)])])
    program.code(0x1010, [op("COPY", [const(1, 8)], reg("RAX"))])
    program.code(0x1014, ret(), length=1)
    program.function("f", 0x1000)
    return _module(program)


def test_a_goal_inside_a_merged_region_is_reached_only_on_a_possible_path() -> None:
    """Forks inside a region go unchecked until the join; what stops there is checked then.

    `x == 5` and then `x == 6` cannot both hold, so reaching 0x1010 would be a goal on a
    path that cannot happen: it must be dropped, not reported.
    """
    impossible = _solve(_nested_equality(6), Goal(addresses=frozenset({0x1010})))
    assert impossible.model is None
    assert impossible.exploration.reached == []
    assert impossible.exploration.statistics.stops[StopReason.INFEASIBLE] >= 1
    assert impossible.exploration.statistics.merges >= 1  # the region did run, and merge
    possible = _solve(_nested_equality(5), Goal(addresses=frozenset({0x1010})))
    assert possible.model == {"x": 5}


class _TimeoutBackend:
    """A solver that never settles: every check times out.

    It stands in for a real solver giving up on a hard query, which is what a deferred
    region's join check can do. A path it cannot disprove must be kept, not dropped.
    """

    name = "timeout"

    def session(self) -> _TimeoutSession:
        return _TimeoutSession()


class _TimeoutSession:
    def add(self, constraint: object) -> None:
        del constraint

    def push(self) -> None:
        pass

    def pop(self) -> None:
        pass

    def check(
        self,
        assumptions: object = (),
        symbols: object = (),
        timeout_ms: int | None = None,
    ) -> CheckResult:
        del assumptions, symbols, timeout_ms
        return CheckResult(Status.TIMEOUT, {}, "timeout")

    def smt2(self, assumptions: object = ()) -> str:
        del assumptions
        return ""


def test_a_merged_path_the_solver_cannot_disprove_is_not_dropped() -> None:
    """A join check that times out must not turn a reachable goal into no goal at all.

    The two sides of the branch merge, then the goal sits past the join. With a solver
    that gives up on every query, the merged path cannot be shown feasible - but it also
    cannot be shown impossible, so it is kept and the goal is still reached.
    """
    program = ProgramBuilder()
    _xor_check(program)
    program.function("f", 0x1000)
    module = _module(program)
    function = module.function_named("f")
    assert function is not None
    solution = solve_function(
        module,
        function,
        {"RDI": sx.symbol("x", 64)},
        Goal(addresses=frozenset({0x100C})),
        _TimeoutBackend(),
    )
    assert solution.exploration.reached, "the merged path was dropped as if impossible"
    assert solution.exploration.statistics.stops[StopReason.INFEASIBLE] == 0
    assert solution.exploration.statistics.merges == 1

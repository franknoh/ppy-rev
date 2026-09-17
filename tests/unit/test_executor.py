from __future__ import annotations

from dataclasses import replace

from ppy_rev.diagnostics import DiagnosticCode
from ppy_rev.execution.interpreter import Interpreter
from ppy_rev.execution.process import enter_call, standard_memory
from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import lift_export
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.solver.z3_backend import Z3Backend
from ppy_rev.symbolic import expr as sx
from ppy_rev.symbolic.executor import Budget, Goal, StopReason
from ppy_rev.symbolic.harness import FunctionSolution, solve_function
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

from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Block,
    Branch,
    Const,
    Function,
    FunctionInput,
    Jump,
    Origin,
    Phi,
    Return,
    UnaryOp,
    UnaryOpcode,
    Var,
)
from ppy_rev.ir.validate import validate_function

ORIGIN = Origin(0x1000, 0)
REGISTERS = {"RAX": 64}


def _function(*blocks: Block) -> Function:
    return Function(
        name="f",
        entry=0x1000,
        inputs=(FunctionInput("RAX", Var(0, 64)),),
        output_registers=("RAX",),
        blocks=blocks,
    )


def _check(function: Function) -> list[str]:
    return validate_function(function, REGISTERS, 64)


def test_well_formed_diamond_with_phi_is_accepted() -> None:
    condition = BinaryOp(BinaryOpcode.EQUAL, Var(1, 8), Var(0, 64), Const(0, 64), ORIGIN)
    function = _function(
        Block(0, 0x1000, (), (condition,), Branch(Var(1, 8), 1, 2, ORIGIN)),
        Block(1, 0x1004, (), (), Jump(3, ORIGIN)),
        Block(2, 0x1008, (), (), Jump(3, ORIGIN)),
        Block(
            3,
            0x100C,
            (Phi(Var(2, 64), ((1, Const(1, 64)), (2, Var(0, 64)))),),
            (),
            Return((Var(2, 64),), None, ORIGIN),
        ),
    )
    assert _check(function) == []


def test_use_that_is_not_dominated_is_rejected() -> None:
    function = _function(
        Block(0, 0x1000, (), (), Branch(Const(1, 8), 1, 2, ORIGIN)),
        Block(
            1,
            0x1004,
            (),
            (UnaryOp(UnaryOpcode.BITWISE_NOT, Var(1, 64), Var(0, 64), ORIGIN),),
            Jump(2, ORIGIN),
        ),
        Block(2, 0x1008, (), (), Return((Var(1, 64),), None, ORIGIN)),
    )
    assert any("does not dominate" in problem for problem in _check(function))


def test_width_violations_and_missing_phi_edges_are_rejected() -> None:
    function = _function(
        Block(
            0,
            0x1000,
            (),
            (BinaryOp(BinaryOpcode.ADD, Var(1, 32), Var(0, 64), Const(1, 64), ORIGIN),),
            Branch(Const(1, 8), 1, 1, ORIGIN),
        ),
        Block(1, 0x1004, (Phi(Var(2, 64), ()),), (), Return((Var(2, 64),), None, ORIGIN)),
    )
    problems = _check(function)
    assert any("add widths" in problem for problem in problems)
    assert any("covers []" in problem for problem in problems)


def test_duplicate_definitions_are_rejected() -> None:
    op = UnaryOp(UnaryOpcode.COPY, Var(0, 64), Const(0, 64), ORIGIN)
    function = _function(Block(0, 0x1000, (), (op,), Return((Var(0, 64),), None, ORIGIN)))
    assert any("defined more than once" in problem for problem in _check(function))

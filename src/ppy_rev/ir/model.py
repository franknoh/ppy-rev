"""RevIR: the semantic center of ppy-rev.

A small, immutable, SSA-form IR over fixed-width bit vectors. Every value carries its
width in bits; signedness belongs to operations, never to values. Every operation keeps
provenance back to the machine instruction and p-code op it came from.

Functions are register machines in SSA form: the machine registers a function may read
arrive as inputs, the registers it may modify leave through `Return`, and a `Call`
passes and receives register state explicitly. Memory is a single implicit byte-addressed
store accessed through `Load` and `Store`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Endianness(StrEnum):
    LITTLE = "little"
    BIG = "big"


def mask(width: int) -> int:
    return (1 << width) - 1


@dataclass(frozen=True, slots=True)
class Var:
    """A reference to an SSA value."""

    id: int
    width: int


@dataclass(frozen=True, slots=True)
class Const:
    value: int
    width: int

    def __post_init__(self) -> None:
        if not 0 <= self.value <= mask(self.width):
            raise ValueError(f"constant {self.value:#x} does not fit in {self.width} bits")


type Operand = Var | Const


@dataclass(frozen=True, slots=True)
class Origin:
    """Provenance: the machine instruction and the index of the p-code op within it."""

    address: int
    pcode_index: int


class BinaryOpcode(StrEnum):
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    UNSIGNED_DIV = "unsigned_div"
    SIGNED_DIV = "signed_div"
    UNSIGNED_REM = "unsigned_rem"
    SIGNED_REM = "signed_rem"
    AND = "and"
    OR = "or"
    XOR = "xor"
    SHIFT_LEFT = "shift_left"
    LOGICAL_SHIFT_RIGHT = "logical_shift_right"
    ARITHMETIC_SHIFT_RIGHT = "arithmetic_shift_right"
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"
    UNSIGNED_LESS = "unsigned_less"
    UNSIGNED_LESS_EQUAL = "unsigned_less_equal"
    SIGNED_LESS = "signed_less"
    SIGNED_LESS_EQUAL = "signed_less_equal"
    UNSIGNED_CARRY = "unsigned_carry"
    SIGNED_CARRY = "signed_carry"
    SIGNED_BORROW = "signed_borrow"
    BOOLEAN_AND = "boolean_and"
    BOOLEAN_OR = "boolean_or"
    BOOLEAN_XOR = "boolean_xor"
    POINTER_ADD = "pointer_add"
    POINTER_SUB = "pointer_sub"
    FLOAT_ADD = "float_add"
    FLOAT_SUB = "float_sub"
    FLOAT_MUL = "float_mul"
    FLOAT_DIV = "float_div"
    FLOAT_EQUAL = "float_equal"
    FLOAT_NOT_EQUAL = "float_not_equal"
    FLOAT_LESS = "float_less"
    FLOAT_LESS_EQUAL = "float_less_equal"


SHIFT_OPCODES = frozenset(
    {
        BinaryOpcode.SHIFT_LEFT,
        BinaryOpcode.LOGICAL_SHIFT_RIGHT,
        BinaryOpcode.ARITHMETIC_SHIFT_RIGHT,
    }
)
COMPARISON_OPCODES = frozenset(
    {
        BinaryOpcode.EQUAL,
        BinaryOpcode.NOT_EQUAL,
        BinaryOpcode.UNSIGNED_LESS,
        BinaryOpcode.UNSIGNED_LESS_EQUAL,
        BinaryOpcode.SIGNED_LESS,
        BinaryOpcode.SIGNED_LESS_EQUAL,
        BinaryOpcode.UNSIGNED_CARRY,
        BinaryOpcode.SIGNED_CARRY,
        BinaryOpcode.SIGNED_BORROW,
    }
)
BOOLEAN_OPCODES = frozenset(
    {BinaryOpcode.BOOLEAN_AND, BinaryOpcode.BOOLEAN_OR, BinaryOpcode.BOOLEAN_XOR}
)
DIVISION_OPCODES = frozenset(
    {
        BinaryOpcode.UNSIGNED_DIV,
        BinaryOpcode.SIGNED_DIV,
        BinaryOpcode.UNSIGNED_REM,
        BinaryOpcode.SIGNED_REM,
    }
)
FLOAT_BINARY_OPCODES = frozenset(
    {
        BinaryOpcode.FLOAT_ADD,
        BinaryOpcode.FLOAT_SUB,
        BinaryOpcode.FLOAT_MUL,
        BinaryOpcode.FLOAT_DIV,
        BinaryOpcode.FLOAT_EQUAL,
        BinaryOpcode.FLOAT_NOT_EQUAL,
        BinaryOpcode.FLOAT_LESS,
        BinaryOpcode.FLOAT_LESS_EQUAL,
    }
)
"""Operations reading their operands as IEEE-754 numbers rather than as integers."""
FLOAT_WIDTHS = frozenset({32, 64})
"""The formats RevIR models: binary32 and binary64. x87's 80-bit format stays unsupported."""


class UnaryOpcode(StrEnum):
    COPY = "copy"
    BITWISE_NOT = "bitwise_not"
    TWOS_COMPLEMENT = "twos_complement"
    BOOLEAN_NOT = "boolean_not"
    ZERO_EXTEND = "zero_extend"
    SIGN_EXTEND = "sign_extend"
    TRUNCATE = "truncate"
    POPCOUNT = "popcount"
    COUNT_LEADING_ZEROS = "count_leading_zeros"
    FLOAT_NEGATE = "float_negate"
    FLOAT_ABSOLUTE = "float_absolute"
    FLOAT_SQUARE_ROOT = "float_square_root"
    FLOAT_IS_NAN = "float_is_nan"
    FLOAT_CEILING = "float_ceiling"
    FLOAT_FLOOR = "float_floor"
    FLOAT_ROUND = "float_round"
    FLOAT_FROM_SIGNED = "float_from_signed"
    FLOAT_TO_FLOAT = "float_to_float"
    FLOAT_TO_SIGNED = "float_to_signed"


FLOAT_UNARY_OPCODES = frozenset(
    {
        UnaryOpcode.FLOAT_NEGATE,
        UnaryOpcode.FLOAT_ABSOLUTE,
        UnaryOpcode.FLOAT_SQUARE_ROOT,
        UnaryOpcode.FLOAT_IS_NAN,
        UnaryOpcode.FLOAT_CEILING,
        UnaryOpcode.FLOAT_FLOOR,
        UnaryOpcode.FLOAT_ROUND,
        UnaryOpcode.FLOAT_FROM_SIGNED,
        UnaryOpcode.FLOAT_TO_FLOAT,
        UnaryOpcode.FLOAT_TO_SIGNED,
    }
)
"""Operations whose operand or result is an IEEE-754 number."""


@dataclass(frozen=True, slots=True)
class BinaryOp:
    opcode: BinaryOpcode
    output: Var
    left: Operand
    right: Operand
    origin: Origin


@dataclass(frozen=True, slots=True)
class UnaryOp:
    opcode: UnaryOpcode
    output: Var
    operand: Operand
    origin: Origin


@dataclass(frozen=True, slots=True)
class Subpiece:
    """`output = truncate(operand >> low_bit)`; p-code SUBPIECE with the offset in bits."""

    output: Var
    operand: Operand
    low_bit: int
    origin: Origin


@dataclass(frozen=True, slots=True)
class Piece:
    """Concatenation: `high` supplies the most significant bits."""

    output: Var
    high: Operand
    low: Operand
    origin: Origin


@dataclass(frozen=True, slots=True)
class Load:
    output: Var
    address: Operand
    origin: Origin


@dataclass(frozen=True, slots=True)
class Store:
    address: Operand
    value: Operand
    origin: Origin


@dataclass(frozen=True, slots=True)
class Phi:
    output: Var
    incoming: tuple[tuple[int, Operand], ...]
    """(predecessor block id, value) pairs, sorted by block id."""


@dataclass(frozen=True, slots=True)
class DirectTarget:
    address: int


@dataclass(frozen=True, slots=True)
class ExternalTarget:
    name: str
    address: int
    """The call-site address of the import (typically a PLT thunk)."""


@dataclass(frozen=True, slots=True)
class IndirectTarget:
    address: Operand
    candidates: tuple[int, ...]
    """Statically recovered possible targets; empty when unknown."""


type CallTarget = DirectTarget | ExternalTarget | IndirectTarget


@dataclass(frozen=True, slots=True)
class Call:
    """Transfer register state to a callee and receive its register state back.

    `arguments` and `results` are aligned with `Module.registers` subsets named by
    `argument_registers` and `result_registers`.
    """

    target: CallTarget
    argument_registers: tuple[str, ...]
    arguments: tuple[Operand, ...]
    result_registers: tuple[str, ...]
    results: tuple[Var, ...]
    origin: Origin


@dataclass(frozen=True, slots=True)
class UserOp:
    """A processor-specific operation (p-code CALLOTHER) with no modeled semantics."""

    name: str
    output: Var | None
    inputs: tuple[Operand, ...]
    origin: Origin


@dataclass(frozen=True, slots=True)
class Unsupported:
    """A p-code operation RevIR does not model. Executing it is an error, never a guess."""

    pcode_opcode: str
    output: Var | None
    inputs: tuple[Operand, ...]
    reason: str
    origin: Origin


type Operation = BinaryOp | UnaryOp | Subpiece | Piece | Load | Store | Call | UserOp | Unsupported


@dataclass(frozen=True, slots=True)
class Jump:
    target: int
    origin: Origin


@dataclass(frozen=True, slots=True)
class Branch:
    """Go to `true_target` when `condition` is non-zero, else `false_target`."""

    condition: Operand
    true_target: int
    false_target: int
    origin: Origin


@dataclass(frozen=True, slots=True)
class IndirectJump:
    address: Operand
    targets: tuple[tuple[int, int], ...]
    """(machine address, block id) pairs for the recovered targets."""
    origin: Origin


@dataclass(frozen=True, slots=True)
class Return:
    """Return to the caller. `values` align with the function's `output_registers`."""

    values: tuple[Operand, ...]
    return_address: Operand | None
    origin: Origin


@dataclass(frozen=True, slots=True)
class TailCall:
    """A jump to another function's entry: a call whose results are returned directly."""

    call: Call
    values: tuple[Operand, ...]
    origin: Origin


@dataclass(frozen=True, slots=True)
class Halt:
    """Control does not continue: a call to a non-returning function precedes this."""

    origin: Origin


@dataclass(frozen=True, slots=True)
class Stop:
    """Lifting could not continue past this point; the reason is a diagnostic."""

    reason: str
    origin: Origin


type Terminator = Jump | Branch | IndirectJump | Return | TailCall | Halt | Stop


@dataclass(frozen=True, slots=True)
class InstructionStart:
    """Machine instruction `address` begins before operation `position` of its block.

    Position `len(operations)` means the instruction only contributes the terminator.
    """

    address: int
    position: int


@dataclass(frozen=True, slots=True)
class Block:
    id: int
    address: int
    phis: tuple[Phi, ...]
    operations: tuple[Operation, ...]
    terminator: Terminator
    instructions: tuple[InstructionStart, ...] = ()


@dataclass(frozen=True, slots=True)
class FunctionInput:
    register: str
    value: Var


@dataclass(frozen=True, slots=True)
class Function:
    name: str
    entry: int
    inputs: tuple[FunctionInput, ...]
    output_registers: tuple[str, ...]
    blocks: tuple[Block, ...]
    """Blocks sorted by id; block 0 is the entry block."""

    def block(self, block_id: int) -> Block:
        return self.blocks[block_id]


@dataclass(frozen=True, slots=True)
class Register:
    """A register variable: a maximal group of overlapping machine register storage."""

    name: str
    offset: int
    width: int


@dataclass(frozen=True, slots=True)
class ExternalFunction:
    name: str
    addresses: tuple[int, ...]
    """Addresses that resolve to this import (PLT thunks and placeholder entries)."""
    no_return: bool
    symbol: str = ""
    """The name the linker sees, which for C++ says which overload this is."""


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    name: str
    start: int
    size: int
    readable: bool
    writable: bool
    executable: bool
    data: bytes | None
    """Initial contents, or None for zero-initialized or unmapped-at-rest regions."""

    @property
    def end(self) -> int:
        return self.start + self.size


@dataclass(frozen=True, slots=True)
class Label:
    address: int
    name: str


@dataclass(frozen=True, slots=True)
class Target:
    architecture: str
    endianness: Endianness
    pointer_width: int
    stack_pointer: str
    program_counter: str


@dataclass(frozen=True, slots=True)
class Module:
    name: str
    target: Target
    registers: tuple[Register, ...]
    memory: tuple[MemoryRegion, ...]
    externals: tuple[ExternalFunction, ...]
    functions: tuple[Function, ...]
    labels: tuple[Label, ...]

    def function_at(self, address: int) -> Function | None:
        for function in self.functions:
            if function.entry == address:
                return function
        return None

    def function_named(self, name: str) -> Function | None:
        for function in self.functions:
            if function.name == name:
                return function
        return None

    def register(self, name: str) -> Register:
        for register in self.registers:
            if register.name == name:
                return register
        raise KeyError(name)


def operation_output(operation: Operation) -> tuple[Var, ...]:
    match operation:
        case BinaryOp() | UnaryOp() | Subpiece() | Piece() | Load():
            return (operation.output,)
        case Call():
            return operation.results
        case UserOp() | Unsupported():
            return () if operation.output is None else (operation.output,)
        case Store():
            return ()


def operation_inputs(operation: Operation) -> tuple[Operand, ...]:
    match operation:
        case BinaryOp():
            return (operation.left, operation.right)
        case UnaryOp() | Subpiece():
            return (operation.operand,)
        case Piece():
            return (operation.high, operation.low)
        case Load():
            return (operation.address,)
        case Store():
            return (operation.address, operation.value)
        case Call():
            target = operation.target
            extra = (target.address,) if isinstance(target, IndirectTarget) else ()
            return extra + operation.arguments
        case UserOp() | Unsupported():
            return operation.inputs


def terminator_inputs(terminator: Terminator) -> tuple[Operand, ...]:
    match terminator:
        case Branch():
            return (terminator.condition,)
        case IndirectJump():
            return (terminator.address,)
        case Return():
            extra = () if terminator.return_address is None else (terminator.return_address,)
            return terminator.values + extra
        case TailCall():
            return operation_inputs(terminator.call) + terminator.values
        case Jump() | Halt() | Stop():
            return ()


def successors(terminator: Terminator) -> tuple[int, ...]:
    match terminator:
        case Jump():
            return (terminator.target,)
        case Branch():
            if terminator.true_target == terminator.false_target:
                return (terminator.true_target,)
            return (terminator.true_target, terminator.false_target)
        case IndirectJump():
            return tuple(sorted({block for _, block in terminator.targets}))
        case Return() | TailCall() | Halt() | Stop():
            return ()

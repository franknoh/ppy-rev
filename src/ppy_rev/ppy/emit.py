"""RevIR → PPy source.

The output is semantic, not decorative: every value is an explicitly masked machine
integer annotated with its PPy fixed-width type, so `ppy check` can prove every width
contract without inserting runtime checks. Functions with a single block are emitted as
straight-line code; anything else uses explicit block dispatch, which preserves arbitrary
control flow exactly. Phis become parallel assignments on the incoming edge.
"""

from __future__ import annotations

import json
import keyword
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from ppy_rev.abi import calling_convention
from ppy_rev.analysis.program import find_main
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.execution.process import (
    INITIAL_STACK_POINTER,
    RETURN_SENTINEL,
    STACK_CANARY,
    STACK_SIZE,
    STACK_START,
    THREAD_BLOCK,
    THREAD_BLOCK_SIZE,
)
from ppy_rev.execution.program import (
    ARGUMENTS_SIZE,
    ARGUMENTS_START,
    HEAP_SIZE,
    HEAP_START,
    LIBC_DATA_SIZE,
    LIBC_DATA_START,
)
from ppy_rev.ir.model import (
    FLOAT_BINARY_OPCODES,
    FLOAT_UNARY_OPCODES,
    BinaryOp,
    BinaryOpcode,
    Block,
    Branch,
    Call,
    Const,
    DirectTarget,
    ExternalTarget,
    Function,
    Halt,
    IndirectJump,
    IndirectTarget,
    Jump,
    Load,
    Module,
    Operand,
    Operation,
    Piece,
    Return,
    Stop,
    Store,
    Subpiece,
    TailCall,
    Terminator,
    UnaryOp,
    UnaryOpcode,
    Unsupported,
    UserOp,
    Var,
    mask,
    operation_output,
)

RUNTIME_NAME = "runtime.ppy"
MODULE_NAME = "module.ppy"
METADATA_NAME = "metadata.json"
PROGRAM_NAME = "program.ppy"
_FIXED_WIDTHS = {8: "u8", 16: "u16", 32: "u32", 64: "u64"}
_RUNTIME_IMPORTS = (
    "Machine",
    "Region",
    "arithmetic_shift_right",
    "count_leading_zeros",
    "popcount",
    "sign_extend",
    "signed",
    "signed_borrow",
    "signed_carry",
    "signed_div",
    "signed_rem",
)
_DATA_CHUNK = 32


@dataclass(frozen=True, slots=True)
class EmittedFunction:
    name: str
    python_name: str
    entry: int
    parameters: tuple[tuple[str, str], ...]
    """(register, parameter name) in call order, after the machine."""
    outputs: tuple[str, ...]
    """Registers of the returned tuple, in order."""


@dataclass(frozen=True, slots=True)
class EmittedModule:
    sources: dict[str, str]
    functions: tuple[EmittedFunction, ...]

    def write(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for name, text in sorted(self.sources.items()):
            (directory / name).write_text(text, encoding="utf-8")


def runtime_source() -> str:
    return files("ppy_rev.ppy").joinpath(RUNTIME_NAME).read_text(encoding="utf-8")


def emit_module(module: Module) -> EmittedModule:
    names = _function_names(module)
    emitted = tuple(
        EmittedFunction(
            name=function.name,
            python_name=names[function.entry],
            entry=function.entry,
            parameters=tuple(
                (item.register, _identifier(item.register.lower())) for item in function.inputs
            ),
            outputs=function.output_registers,
        )
        for function in module.functions
    )
    by_entry = {function.entry: function for function in emitted}
    lines = [
        f'"""PPy lifted from {module.name} ({module.target.architecture}) by ppy-rev."""',
        "",
        "from ppy import u8, u16, u32, u64",
        "",
        "from runtime import (",
        *(f"    {name}," for name in _RUNTIME_IMPORTS),
        ")",
    ]
    for function in module.functions:
        lines.extend(("", ""))
        lines.extend(_FunctionEmitter(module, function, by_entry).emit())
    lines.extend(("", ""))
    lines.extend(_regions(module))
    metadata = {
        "module": module.name,
        "target": {
            "architecture": module.target.architecture,
            "endianness": str(module.target.endianness),
            "pointer_width": module.target.pointer_width,
        },
        "functions": [
            {
                "name": function.name,
                "python_name": function.python_name,
                "entry": f"{function.entry:#x}",
                "parameters": [
                    {"register": register, "name": name} for register, name in function.parameters
                ],
                "returns": list(function.outputs),
            }
            for function in emitted
        ],
        "externals": [
            {"name": external.name, "addresses": [f"{a:#x}" for a in external.addresses]}
            for external in module.externals
        ],
    }
    sources = {
        RUNTIME_NAME: runtime_source(),
        MODULE_NAME: "\n".join(lines) + "\n",
        METADATA_NAME: json.dumps(metadata, indent=2) + "\n",
    }
    entry = _entry_function(module, by_entry)
    if entry is not None:
        sources[PROGRAM_NAME] = "\n".join(_program(module, entry)) + "\n"
    return EmittedModule(sources=sources, functions=emitted)


def _entry_function(module: Module, emitted: dict[int, EmittedFunction]) -> EmittedFunction | None:
    """The lifted `main`, when the program has one to start from."""
    try:
        return emitted.get(find_main(module).entry)
    except PpyRevError:
        return None


def _program(module: Module, entry: EmittedFunction) -> list[str]:
    """A runnable front end: arguments and standard input in, output and status out."""
    convention = calling_convention(module.target)
    width = module.target.pointer_width
    values = {
        convention.integer_parameters[0]: "count",
        convention.integer_parameters[1]: "table",
        convention.stack_pointer: "stack",
        "FS_OFFSET": f"{THREAD_BLOCK:#x}",
    }
    passed = ", ".join(values.get(register, "0") for register, _ in entry.parameters)
    returns = entry.outputs.index(convention.integer_returns[0])
    return [
        '"""Run the lifted program: `ppy program.ppy -- ARGUMENTS`, standard input included."""',
        "",
        "import sys",
        "",
        "import ppy",
        "",
        f"from module import {entry.python_name}, regions",
        "from runtime import Exited, Machine, Region",
        "",
        f"STACK = {STACK_START:#x}",
        f"STACK_SIZE = {STACK_SIZE:#x}",
        f"STACK_POINTER = {INITIAL_STACK_POINTER:#x}",
        f"THREAD_BLOCK = {THREAD_BLOCK:#x}",
        f"THREAD_BLOCK_SIZE = {THREAD_BLOCK_SIZE:#x}",
        f"CANARY = {STACK_CANARY:#x}",
        f"RETURN_SENTINEL = {RETURN_SENTINEL:#x}",
        f"ARGUMENTS = {ARGUMENTS_START:#x}",
        f"ARGUMENTS_SIZE = {ARGUMENTS_SIZE:#x}",
        f"LIBC = {LIBC_DATA_START:#x}",
        f"LIBC_SIZE = {LIBC_DATA_SIZE:#x}",
        f"HEAP = {HEAP_START:#x}",
        f"HEAP_SIZE = {HEAP_SIZE:#x}",
        f"POINTER_BYTES = {width // 8}",
        "",
        "",
        "def run(arguments: list[bytes], stdin: bytes) -> tuple[int, bytes]:",
        '    """The program image plus a process around it: argv, a stack, a heap."""',
        "    around: list[Region] = [",
        '        Region("[stack]", STACK, STACK_SIZE, True, b""),',
        '        Region("[tls]", THREAD_BLOCK, THREAD_BLOCK_SIZE, True, b""),',
        '        Region("[args]", ARGUMENTS, ARGUMENTS_SIZE, True, b""),',
        '        Region("[libc]", LIBC, LIBC_SIZE, True, b""),',
        '        Region("[heap]", HEAP, HEAP_SIZE, True, b""),',
        "    ]",
        "    m: Machine = Machine(regions() + around, stdin)",
        "    m.memory.store(THREAD_BLOCK, POINTER_BYTES, THREAD_BLOCK)",
        "    m.memory.store(THREAD_BLOCK + 0x28, POINTER_BYTES, CANARY)",
        "    cursor: int = ARGUMENTS",
        "    pointers: list[int] = []",
        "    for argument in arguments:",
        "        pointers.append(cursor)",
        "        m.write_at(cursor, [byte for byte in argument])",
        "        m.memory.store(cursor + len(argument), 1, 0)",
        "        cursor += len(argument) + 1",
        f"    table: int = (cursor + 15) & {mask(width) - 15:#x}",
        "    for index in range(len(pointers)):",
        "        m.memory.store(table + POINTER_BYTES * index, POINTER_BYTES, pointers[index])",
        "    m.memory.store(table + POINTER_BYTES * len(pointers), POINTER_BYTES, 0)",
        "    stack: int = STACK_POINTER - POINTER_BYTES",
        f"    count: int = len(arguments) & {mask(width):#x}",
        "    m.memory.store(stack, POINTER_BYTES, RETURN_SENTINEL)",
        "    try:",
        f"        outputs = {entry.python_name}(m, {passed})",
        "    except Exited as exit_status:",
        "        return exit_status.code, bytes(m.output)",
        f"    return outputs[{returns}] & 0xFF, bytes(m.output)",
        "",
        "",
        "def standard_input() -> bytes:",
        '    """Every line of standard input, each ending in a newline."""',
        '    text: str = ""',
        "    while True:",
        "        try:",
        "            line: str = ppy.input[str]()",
        "        except EOFError:",
        "            break",
        '        text += line + "\\n"',
        '    return text.encode("latin-1")',
        "",
        "",
        "def start() -> int:",
        "    arguments: list[bytes] = [item.encode() for item in sys.argv]",
        "    status, output = run(arguments, standard_input())",
        '    print(output.decode("latin-1"), end="")',
        "    return status",
        "",
        "",
        'if __name__ == "__main__":',
        "    raise SystemExit(start())",
    ]


def _identifier(text: str) -> str:
    cleaned = re.sub(r"\W", "_", text, flags=re.ASCII) or "_"
    if cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    if keyword.iskeyword(cleaned) or keyword.issoftkeyword(cleaned) or cleaned in _RESERVED:
        cleaned = f"{cleaned}_"
    return cleaned


_RESERVED = frozenset(
    {"m", "block", "results", "u8", "u16", "u32", "u64", "regions", *_RUNTIME_IMPORTS}
)


def _function_names(module: Module) -> dict[int, str]:
    names: dict[int, str] = {}
    taken: set[str] = set()
    for function in module.functions:
        name = _identifier(function.name)
        if name in taken or re.fullmatch(r"v\d+", name):
            name = f"{name}_{function.entry:x}"
        taken.add(name)
        names[function.entry] = name
    return names


def _type(width: int) -> str:
    return _FIXED_WIDTHS.get(width, "int")


def _literal(value: int) -> str:
    return str(value) if value < 10 else f"{value:#x}"


def _mask(width: int) -> str:
    return f"{mask(width):#x}"


class _FunctionEmitter:
    def __init__(
        self, module: Module, function: Function, functions: dict[int, EmittedFunction]
    ) -> None:
        self.module = module
        self.function = function
        self.functions = functions
        self.externals = {
            address: external.name
            for external in module.externals
            for address in external.addresses
        }
        self.names: dict[int, str] = {
            item.value.id: _identifier(item.register.lower()) for item in function.inputs
        }
        self.dispatch = len(function.blocks) > 1
        self.declared: set[int] = set(self.names)
        self._temporaries = 0

    def name(self, var: Var) -> str:
        return self.names.get(var.id, f"v{var.id}")

    def operand(self, operand: Operand) -> str:
        if isinstance(operand, Const):
            return _literal(operand.value)
        return self.name(operand)

    def target(self, var: Var) -> str:
        """Assignment target; annotated at its first definition in straight-line code."""
        if var.id in self.declared:
            return self.name(var)
        self.declared.add(var.id)
        return f"{self.name(var)}: {_type(var.width)}"

    # -- function ------------------------------------------------------------------------

    def emit(self) -> list[str]:
        function = self.function
        emitted = self.functions[function.entry]
        parameters = ", ".join(
            ["m: Machine"]
            + [
                f"{name}: {_type(item.value.width)}"
                for (_, name), item in zip(emitted.parameters, function.inputs, strict=True)
            ]
        )
        returns = ", ".join(_type(width) for width in self._output_widths())
        lines = [
            f"def {emitted.python_name}({parameters}) -> tuple[{returns or '()'}]:",
            f'    """{function.name} @ {function.entry:#x}; returns '
            f'({", ".join(function.output_registers)})."""',
        ]
        if not self.dispatch:
            lines.extend(self.block(function.blocks[0], indent="    "))
            return lines
        for var in self._definitions():
            if var.id not in self.declared:
                self.declared.add(var.id)
                lines.append(f"    {self.name(var)}: {_type(var.width)} = 0")
        lines.append("    block: int = 0")
        lines.append("    while True:")
        for index, block in enumerate(function.blocks):
            keyword_ = "if" if index == 0 else "elif"
            lines.append(f"        {keyword_} block == {block.id}:  # {block.address:#x}")
            lines.extend(self.block(block, indent="            "))
        lines.append("        else:")
        lines.append('            raise AssertionError("unknown block")')
        return lines

    def _output_widths(self) -> list[int]:
        widths = {register.name: register.width for register in self.module.registers}
        return [widths[register] for register in self.function.output_registers]

    def _definitions(self) -> list[Var]:
        definitions: list[Var] = []
        for block in self.function.blocks:
            definitions.extend(phi.output for phi in block.phis)
            for operation in block.operations:
                definitions.extend(operation_output(operation))
            if isinstance(block.terminator, TailCall):
                definitions.extend(block.terminator.call.results)
        return definitions

    # -- blocks --------------------------------------------------------------------------

    def block(self, block: Block, indent: str) -> list[str]:
        lines: list[str] = []
        for operation in block.operations:
            lines.extend(indent + line for line in self.operation(operation))
        lines.extend(indent + line for line in self.terminator(block, block.terminator))
        return lines or [f"{indent}pass"]

    def edge(self, source: int, target: int) -> list[str]:
        phis = self.function.blocks[target].phis
        copies = [
            (phi.output, value)
            for phi in phis
            for predecessor, value in phi.incoming
            if predecessor == source
        ]
        lines: list[str] = []
        if copies:
            targets = ", ".join(self.name(output) for output, _ in copies)
            values = ", ".join(self.operand(value) for _, value in copies)
            lines.append(f"{targets} = {values}")
        lines.append(f"block = {target}")
        return lines

    def terminator(self, block: Block, terminator: Terminator) -> list[str]:
        match terminator:
            case Jump():
                return self.edge(block.id, terminator.target)
            case Branch():
                return [
                    f"if {self.operand(terminator.condition)} != 0:",
                    *("    " + line for line in self.edge(block.id, terminator.true_target)),
                    "else:",
                    *("    " + line for line in self.edge(block.id, terminator.false_target)),
                ]
            case IndirectJump():
                lines: list[str] = []
                address = self.operand(terminator.address)
                for index, (target, block_id) in enumerate(terminator.targets):
                    keyword_ = "if" if index == 0 else "elif"
                    lines.append(f"{keyword_} {address} == {target:#x}:")
                    lines.extend("    " + line for line in self.edge(block.id, block_id))
                message = (
                    f"indirect jump at {terminator.origin.address:#x} to an unrecovered target"
                )
                if lines:
                    lines.append("else:")
                    lines.append(f"    raise NotImplementedError({message!r})")
                else:
                    lines.append(f"raise NotImplementedError({message!r})")
                return lines
            case Return():
                values = [self.operand(value) for value in terminator.values]
                return [f"return ({', '.join(values)}{',' if len(values) == 1 else ''})"]
            case TailCall():
                lines = self.call(terminator.call)
                values = [self.operand(value) for value in terminator.values]
                lines.append(f"return ({', '.join(values)}{',' if len(values) == 1 else ''})")
                return lines
            case Halt():
                message = f"non-returning call before {terminator.origin.address:#x} returned"
                return [f"raise RuntimeError({message!r})"]
            case Stop():
                message = f"{terminator.reason} (at {terminator.origin.address:#x})"
                return [f"raise NotImplementedError({message!r})"]

    # -- operations ----------------------------------------------------------------------

    def operation(self, operation: Operation) -> list[str]:
        match operation:
            case BinaryOp(opcode=opcode) if opcode in FLOAT_BINARY_OPCODES:
                return [f"raise NotImplementedError({self._float_message(operation)!r})"]
            case UnaryOp(opcode=opcode) if opcode in FLOAT_UNARY_OPCODES:
                return [f"raise NotImplementedError({self._float_message(operation)!r})"]
            case BinaryOp():
                return [f"{self.target(operation.output)} = {self.binary(operation)}"]
            case UnaryOp():
                return [f"{self.target(operation.output)} = {self.unary(operation)}"]
            case Subpiece(output=output, operand=operand, low_bit=low_bit):
                value = self.operand(operand)
                return [f"{self.target(output)} = ({value} >> {low_bit}) & {_mask(output.width)}"]
            case Piece(output=output, high=high, low=low):
                expression = f"({self.operand(high)} << {low.width}) | {self.operand(low)}"
                return [f"{self.target(output)} = {expression}"]
            case Load(output=output, address=address):
                return [f"{self.target(output)} = {self.load(address, output.width)}"]
            case Store(address=address, value=value):
                size = value.width // 8
                return [f"m.memory.store({self.operand(address)}, {size}, {self.operand(value)})"]
            case Call():
                return self.call(operation)
            case UserOp():
                message = (
                    f"user operation {operation.name} at {operation.origin.address:#x} "
                    "has no modeled semantics"
                )
                return [f"raise NotImplementedError({message!r})"]
            case Unsupported():
                message = f"{operation.reason} at {operation.origin.address:#x}"
                return [f"raise NotImplementedError({message!r})"]

    def load(self, address: Operand, width: int) -> str:
        if width in _FIXED_WIDTHS:
            return f"m.memory.load_{_FIXED_WIDTHS[width]}({self.operand(address)})"
        return f"m.memory.load({self.operand(address)}, {width // 8})"

    @staticmethod
    def _float_message(operation: BinaryOp | UnaryOp) -> str:
        """PPy emission stays integer-only; solving models these, running the PPy does not."""
        return (
            f"{operation.opcode} at {operation.origin.address:#x}: "
            "PPy emission does not model floating point"
        )

    def binary(self, op: BinaryOp) -> str:
        left, right = self.operand(op.left), self.operand(op.right)
        width = op.left.width
        m = _mask(width)
        match op.opcode:
            case (
                BinaryOpcode.FLOAT_ADD
                | BinaryOpcode.FLOAT_SUB
                | BinaryOpcode.FLOAT_MUL
                | BinaryOpcode.FLOAT_DIV
                | BinaryOpcode.FLOAT_EQUAL
                | BinaryOpcode.FLOAT_NOT_EQUAL
                | BinaryOpcode.FLOAT_LESS
                | BinaryOpcode.FLOAT_LESS_EQUAL
            ):
                raise AssertionError(f"{op.opcode} is refused before it reaches here")
            case BinaryOpcode.ADD | BinaryOpcode.POINTER_ADD:
                if isinstance(op.right, Const) and op.right.value > mask(width) - 0x10000:
                    # Adding a small negative constant reads better as a subtraction.
                    negated = _literal(mask(width) + 1 - op.right.value)
                    return f"({left} - {negated}) & {m}"
                return f"({left} + {right}) & {m}"
            case BinaryOpcode.SUB | BinaryOpcode.POINTER_SUB:
                return f"({left} - {right}) & {m}"
            case BinaryOpcode.MUL:
                return f"({left} * {right}) & {m}"
            case BinaryOpcode.UNSIGNED_DIV:
                return f"{left} // {right}"
            case BinaryOpcode.UNSIGNED_REM:
                return f"{left} % {right}"
            case BinaryOpcode.SIGNED_DIV:
                return f"signed_div({left}, {right}, {width}) & {m}"
            case BinaryOpcode.SIGNED_REM:
                return f"signed_rem({left}, {right}, {width}) & {m}"
            case BinaryOpcode.AND | BinaryOpcode.BOOLEAN_AND:
                return f"{left} & {right}"
            case BinaryOpcode.OR | BinaryOpcode.BOOLEAN_OR:
                return f"{left} | {right}"
            case BinaryOpcode.XOR | BinaryOpcode.BOOLEAN_XOR:
                return f"{left} ^ {right}"
            case BinaryOpcode.SHIFT_LEFT:
                return f"(({left} << {right}) & {m}) if {right} < {width} else 0"
            case BinaryOpcode.LOGICAL_SHIFT_RIGHT:
                return f"{left} >> {right}"
            case BinaryOpcode.ARITHMETIC_SHIFT_RIGHT:
                return f"arithmetic_shift_right({left}, {right}, {width}) & {m}"
            case BinaryOpcode.EQUAL:
                return f"1 if {left} == {right} else 0"
            case BinaryOpcode.NOT_EQUAL:
                return f"1 if {left} != {right} else 0"
            case BinaryOpcode.UNSIGNED_LESS:
                return f"1 if {left} < {right} else 0"
            case BinaryOpcode.UNSIGNED_LESS_EQUAL:
                return f"1 if {left} <= {right} else 0"
            case BinaryOpcode.SIGNED_LESS:
                return f"1 if signed({left}, {width}) < signed({right}, {width}) else 0"
            case BinaryOpcode.SIGNED_LESS_EQUAL:
                return f"1 if signed({left}, {width}) <= signed({right}, {width}) else 0"
            case BinaryOpcode.UNSIGNED_CARRY:
                return f"1 if {left} + {right} > {m} else 0"
            case BinaryOpcode.SIGNED_CARRY:
                return f"signed_carry({left}, {right}, {width}) & 1"
            case BinaryOpcode.SIGNED_BORROW:
                return f"signed_borrow({left}, {right}, {width}) & 1"

    def unary(self, op: UnaryOp) -> str:
        value = self.operand(op.operand)
        source, width = op.operand.width, op.output.width
        match op.opcode:
            case (
                UnaryOpcode.FLOAT_NEGATE
                | UnaryOpcode.FLOAT_ABSOLUTE
                | UnaryOpcode.FLOAT_SQUARE_ROOT
                | UnaryOpcode.FLOAT_IS_NAN
                | UnaryOpcode.FLOAT_CEILING
                | UnaryOpcode.FLOAT_FLOOR
                | UnaryOpcode.FLOAT_ROUND
                | UnaryOpcode.FLOAT_FROM_SIGNED
                | UnaryOpcode.FLOAT_TO_FLOAT
                | UnaryOpcode.FLOAT_TO_SIGNED
            ):
                raise AssertionError(f"{op.opcode} is refused before it reaches here")
            case UnaryOpcode.COPY | UnaryOpcode.ZERO_EXTEND:
                return value
            case UnaryOpcode.BITWISE_NOT:
                return f"{value} ^ {_mask(source)}"
            case UnaryOpcode.TWOS_COMPLEMENT:
                return f"-{value} & {_mask(source)}"
            case UnaryOpcode.BOOLEAN_NOT:
                return f"{value} ^ 1"
            case UnaryOpcode.SIGN_EXTEND:
                return f"sign_extend({value}, {source}, {width}) & {_mask(width)}"
            case UnaryOpcode.TRUNCATE:
                return f"{value} & {_mask(width)}"
            case UnaryOpcode.POPCOUNT:
                return f"popcount({value}) & {_mask(width)}"
            case UnaryOpcode.COUNT_LEADING_ZEROS:
                return f"count_leading_zeros({value}, {source}) & {_mask(width)}"

    def call(self, call: Call) -> list[str]:
        arguments = dict(zip(call.argument_registers, call.arguments, strict=True))
        results = dict(zip(call.result_registers, call.results, strict=True))
        origin = f"{call.origin.address:#x}"
        match call.target:
            case ExternalTarget(name=name):
                return self.external_call(name, arguments, results, origin)
            case DirectTarget(address=address) if address in self.functions:
                callee = self.functions[address]
                passed = ", ".join(
                    ["m"] + [self.operand(arguments[register]) for register, _ in callee.parameters]
                )
                unpacked = self._unpack(callee.outputs, results)
                return [f"{unpacked} = {callee.python_name}({passed})  # {origin}"]
            case DirectTarget(address=address) if address in self.externals:
                return self.external_call(self.externals[address], arguments, results, origin)
            case DirectTarget(address=address):
                message = f"call at {origin} to {address:#x}, which was not lifted"
                return [f"raise NotImplementedError({message!r})"]
            case IndirectTarget():
                message = f"indirect call at {origin} is not modeled"
                return [f"raise NotImplementedError({message!r})"]

    def external_call(
        self, name: str, arguments: dict[str, Operand], results: dict[str, Var], origin: str
    ) -> list[str]:
        self._temporaries += 1
        temporary = f"results{self._temporaries}"
        passed = ", ".join(
            f'"{register}": {self.operand(value)}' for register, value in arguments.items()
        )
        lines = [f"{temporary} = m.external({name!r}, {{{passed}}})  # {origin}"]
        lines.extend(
            f'{self.target(result)} = {temporary}.get("{register}", 0) & {_mask(result.width)}'
            for register, result in results.items()
        )
        return lines

    def _unpack(self, outputs: tuple[str, ...], results: dict[str, Var]) -> str:
        names: list[str] = []
        for register in outputs:
            result = results.get(register)
            names.append("_" if result is None else self.name(result))
            if result is not None:
                self.declared.add(result.id)
        return f"({', '.join(names)}{',' if len(names) == 1 else ''})"


def _regions(module: Module) -> list[str]:
    lines = ["def regions() -> list[Region]:", '    """The program image."""', "    return ["]
    for region in module.memory:
        data = region.data or b""
        lines.append(
            f"        Region({region.name!r}, {region.start:#x}, {region.size:#x}, "
            f"{region.writable}, "
        )
        if not data:
            lines[-1] += 'b""),'
            continue
        lines[-1] = lines[-1].rstrip()
        for offset in range(0, len(data), _DATA_CHUNK):
            lines.append(f"            {data[offset : offset + _DATA_CHUNK]!r}")
        lines.append("        ),")
    lines.append("    ]")
    lines.extend(("", "", "def new_machine() -> Machine:", "    return Machine(regions())"))
    return lines

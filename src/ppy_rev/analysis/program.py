"""Whole-program facts: the entry function, call graph, and referenced strings."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from ppy_rev.abi import calling_convention
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.ir.model import (
    Call,
    CallTarget,
    Const,
    DirectTarget,
    ExternalTarget,
    Function,
    IndirectTarget,
    Module,
    Operand,
    TailCall,
    operation_inputs,
    terminator_inputs,
)
from ppy_rev.summaries.libc import canonical_name, model_name

_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def calls(function: Function) -> Iterator[tuple[Call, int]]:
    """Every call in `function`, with the id of its block (tail calls included)."""
    for block in function.blocks:
        for operation in block.operations:
            if isinstance(operation, Call):
                yield operation, block.id
        if isinstance(block.terminator, TailCall):
            yield block.terminator.call, block.id


def external_name(module: Module, call: Call) -> str | None:
    """The library function a call reaches: directly, or through a resolved GOT entry."""
    match call.target:
        case ExternalTarget(name=name, address=address):
            return _external_at(module, address) or canonical_name(name)
        case DirectTarget(address=address):
            return _external_at(module, address)
        case IndirectTarget(candidates=candidates) if candidates:
            names = {_external_at(module, address) for address in candidates}
            return names.pop() if len(names) == 1 else None
        case IndirectTarget():
            return None


def _external_at(module: Module, address: int) -> str | None:
    for external in module.externals:
        if address in external.addresses:
            return model_name(external)
    return None


def find_main(module: Module) -> Function:
    main = module.function_named("main")
    if main is not None:
        return main
    first_argument = calling_convention(module.target).integer_parameters[0]
    for function in module.functions:
        for call, _ in calls(function):
            if external_name(module, call) != "__libc_start_main":
                continue
            arguments = dict(zip(call.argument_registers, call.arguments, strict=True))
            candidate = arguments.get(first_argument)
            if isinstance(candidate, Const):
                found = module.function_at(candidate.value)
                if found is not None:
                    return found
    raise PpyRevError("could not find main: no symbol, and no __libc_start_main call names it")


def reachable_functions(module: Module, root: Function) -> list[Function]:
    """Functions reachable from `root` through its calls, in discovery order.

    A call through a function pointer counts when the target was recovered: a program
    that dispatches through a table — a menu, a VM, an obfuscated checker — reaches most
    of itself that way, and nothing it does there would otherwise be seen.
    """
    seen = {root.entry}
    order = [root]
    for function in order:
        for call, _ in calls(function):
            for address in _callees(call.target):
                callee = module.function_at(address)
                if callee is not None and callee.entry not in seen:
                    seen.add(callee.entry)
                    order.append(callee)
    return order


def _callees(target: CallTarget) -> tuple[int, ...]:
    match target:
        case DirectTarget(address=address):
            return (address,)
        case IndirectTarget(candidates=candidates):
            return candidates
        case _:
            return ()


_BEFORE_MAIN = frozenset(
    {
        "abort",
        "alarm",
        "exit",
        "fgets",
        "fgetc",
        "fork",
        "fread",
        "fscanf",
        "getchar",
        "getline",
        "gets",
        "kill",
        "mprotect",
        "personality",
        "prctl",
        "ptrace",
        "read",
        "scanf",
        "signal",
        "sigaction",
        "system",
    }
)
"""Library calls that make an initializer able to change, or decide, what main sees."""


@dataclass(frozen=True, slots=True)
class Initializer:
    """A function the loader runs before main, and the notable library calls it reaches."""

    name: str
    address: int
    library_calls: tuple[str, ...]


def initializer_functions(module: Module) -> tuple[Function, ...]:
    """The lifted constructors the loader runs before main, in the order it runs them."""
    width = module.target.pointer_width // 8
    order: Literal["little", "big"] = module.target.endianness.value
    found: list[Function] = []
    for name in (".preinit_array", ".init_array"):
        for region in module.memory:
            if region.name != name or region.data is None:
                continue
            for offset in range(0, len(region.data) - width + 1, width):
                address = int.from_bytes(region.data[offset : offset + width], order)
                function = module.function_at(address)
                if function is not None and function not in found:
                    found.append(function)
    return tuple(found)


def deferred_initializers(module: Module) -> tuple[Initializer, ...]:
    """Constructors whose behaviour depends on something only solving could decide.

    Reading the input, checking for a debugger, exiting: running such a constructor
    concretely before main would fix an answer to a guess. They are reported instead;
    the ones every compiler emits reach none of these calls and simply run.
    """
    found: list[Initializer] = []
    for function in initializer_functions(module):
        names = sorted(
            {
                name
                for reached in reachable_functions(module, function)
                for call, _ in calls(reached)
                if (name := external_name(module, call)) is not None and name in _BEFORE_MAIN
            }
        )
        if names:
            found.append(Initializer(function.name, function.entry, tuple(names)))
    return tuple(found)


@dataclass(frozen=True, slots=True)
class ExternalObjects:
    """Where an import's *data* object lives: an address the program image does not hold.

    Ghidra gives every imported symbol an address in a block of its own, outside the
    sections the loader would map, and code reaching `std::cin` or `environ` through the
    GOT ends up reading there. Such a read faults, but the program is not wrong — the
    model is missing — so those addresses are recognized rather than called a crash.
    """

    names: dict[int, str]
    start: int
    end: int

    def __contains__(self, address: int) -> bool:
        return self.start <= address < self.end

    def name_at(self, address: int) -> str | None:
        return self.names.get(address)


def external_objects(module: Module) -> ExternalObjects:
    """The labels that fall outside every mapped region, and the span they occupy."""
    names = {
        label.address: label.name
        for label in module.labels
        if not any(region.start <= label.address < region.end for region in module.memory)
    }
    if not names:
        return ExternalObjects({}, 0, 0)
    step = module.target.pointer_width // 8
    return ExternalObjects(names, min(names), max(names) + step)


def executable_address(module: Module, address: int) -> int:
    """`address` if an instruction was lifted there, else the next one in the same function.

    A function's first instruction is often `endbr64`, which describes no operation and so
    has nothing to reach: a goal on a function entry would otherwise be unreachable by
    construction. Raises when the address is not inside a lifted function at all.
    """
    for function in module.functions:
        starts = sorted(
            instruction.address for block in function.blocks for instruction in block.instructions
        )
        if not starts or not starts[0] - 16 <= address <= starts[-1]:
            continue
        if address in starts:
            return address
        later = [start for start in starts if start > address]
        if later and (function.entry <= address or address >= starts[0]):
            return later[0]
    raise PpyRevError(f"no lifted instruction at {address:#x}")


@dataclass(frozen=True, slots=True)
class StringReference:
    text: bytes
    address: int
    function: str
    instruction: int
    """The call receiving the string, or the instruction using its address."""
    call: str | None
    """Name of the function the string is passed to, if it is passed to a call."""
    register: str | None
    """The argument register carrying the string's address into that call."""
    external: bool = False
    """The call goes to an imported library function."""


def read_c_string(module: Module, address: int, limit: int = 512) -> bytes | None:
    """A printable, NUL-terminated string stored in initialized non-executable data."""
    for region in module.memory:
        if region.data is None or region.executable or not region.start <= address < region.end:
            continue
        offset = address - region.start
        end = region.data.find(b"\0", offset, offset + limit + 1)
        if end < 0:
            return None
        text = region.data[offset:end]
        if not text or any(byte not in _PRINTABLE for byte in text):
            return None
        return text
    return None


def string_references(
    module: Module, functions: list[Function] | None = None
) -> list[StringReference]:
    """Strings whose addresses reach a call argument (possibly through phis) or an operation.

    Passing through phis matters: compilers often select between messages without a branch
    (`cmov`), so the instruction mentioning a string runs on every path, and only the call's
    argument tells which message is printed.
    """
    found: dict[tuple[int, int, str], StringReference] = {}
    for function in functions if functions is not None else list(module.functions):
        _FunctionStrings(module, function, found).collect()
    return [found[key] for key in sorted(found)]


class _FunctionStrings:
    def __init__(
        self,
        module: Module,
        function: Function,
        found: dict[tuple[int, int, str], StringReference],
    ) -> None:
        self.module = module
        self.function = function
        self.found = found
        self.pointer_width = module.target.pointer_width
        self.phis = {phi.output.id: phi for block in function.blocks for phi in block.phis}

    def constants(self, operand: Operand, seen: frozenset[int] = frozenset()) -> set[int]:
        if isinstance(operand, Const):
            return {operand.value} if operand.width == self.pointer_width else set()
        phi = self.phis.get(operand.id)
        if phi is None or operand.id in seen:
            return set()
        reached: set[int] = set()
        for _, value in phi.incoming:
            reached |= self.constants(value, seen | {operand.id})
        return reached

    def add(
        self,
        value: int,
        instruction: int,
        call: str | None,
        register: str | None,
        external: bool = False,
    ) -> None:
        text = read_c_string(self.module, value)
        key = (instruction, value, register or "")
        if text is not None and key not in self.found:
            self.found[key] = StringReference(
                text, value, self.function.name, instruction, call, register, external
            )

    def collect(self) -> None:
        for call, _ in calls(self.function):
            library = external_name(self.module, call)
            receiver = library or _callee_name(self.module, call)
            for register, argument in zip(call.argument_registers, call.arguments, strict=True):
                for value in self.constants(argument):
                    self.add(value, call.origin.address, receiver, register, library is not None)
        for block in self.function.blocks:
            for operation in block.operations:
                if isinstance(operation, Call):
                    continue
                for value in operation_inputs(operation):
                    if isinstance(value, Const) and value.width == self.pointer_width:
                        self.add(value.value, operation.origin.address, None, None)
            for value in terminator_inputs(block.terminator):
                if isinstance(value, Const) and value.width == self.pointer_width:
                    self.add(value.value, block.terminator.origin.address, None, None)


def _callee_name(module: Module, call: Call) -> str | None:
    if isinstance(call.target, DirectTarget):
        callee = module.function_at(call.target.address)
        return None if callee is None else callee.name
    return None

"""Whole-program facts: the entry function, call graph, and referenced strings."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from ppy_rev.abi import calling_convention
from ppy_rev.diagnostics import PpyRevError
from ppy_rev.ir.model import (
    Call,
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
from ppy_rev.summaries.libc import canonical_name

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
    match call.target:
        case ExternalTarget(name=name):
            return canonical_name(name)
        case DirectTarget(address=address):
            for external in module.externals:
                if address in external.addresses:
                    return canonical_name(external.name)
            return None
        case IndirectTarget():
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
    """Functions reachable from `root` through direct calls, in discovery order."""
    seen = {root.entry}
    order = [root]
    for function in order:
        for call, _ in calls(function):
            if isinstance(call.target, DirectTarget):
                callee = module.function_at(call.target.address)
                if callee is not None and callee.entry not in seen:
                    seen.add(callee.entry)
                    order.append(callee)
    return order


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

    def add(self, value: int, instruction: int, call: str | None, register: str | None) -> None:
        text = read_c_string(self.module, value)
        key = (instruction, value, register or "")
        if text is not None and key not in self.found:
            self.found[key] = StringReference(
                text, value, self.function.name, instruction, call, register
            )

    def collect(self) -> None:
        for call, _ in calls(self.function):
            receiver = external_name(self.module, call) or _callee_name(self.module, call)
            for register, argument in zip(call.argument_registers, call.arguments, strict=True):
                for value in self.constants(argument):
                    self.add(value, call.origin.address, receiver, register)
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

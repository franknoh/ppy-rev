"""Discovering which user-controlled inputs a program reads.

Standard input is recognised by calls to reading functions reachable from main. Command
line arguments are found by following where main's argv pointer flows: through pointer
arithmetic, stack slots, phis, and calls into lifted helpers, until an `argv[k]` string is
dereferenced or handed to a library function.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ppy_rev.abi import calling_convention
from ppy_rev.analysis.program import calls, external_name, reachable_functions
from ppy_rev.ir.model import (
    BinaryOp,
    BinaryOpcode,
    Call,
    Const,
    DirectTarget,
    Function,
    Load,
    Module,
    Operand,
    Phi,
    Store,
    Var,
    mask,
)
from ppy_rev.simplify.memory import CanonicalAddress

STDIN_READERS = frozenset(
    {"read", "fgets", "getchar", "gets", "fread", "getline", "scanf", "__isoc99_scanf", "fgetc"}
)
"""Library functions whose use means the program consumes standard input."""


class InputKind(StrEnum):
    ARGV = "argv"
    STDIN = "stdin"


@dataclass(frozen=True, slots=True)
class InputCandidate:
    kind: InputKind
    index: int | None
    evidence: tuple[str, ...]


type _Tag = tuple[str, int]
"""("array", byte offset into argv) or ("string", k) for a pointer into argv[k]."""


def discover_inputs(module: Module, main: Function) -> list[InputCandidate]:
    candidates = [
        InputCandidate(InputKind.ARGV, index, tuple(sorted(evidence)))
        for index, evidence in sorted(_argv_uses(module, main).items())
        if index > 0
    ]
    stdin_evidence: list[str] = []
    for function in reachable_functions(module, main):
        for call, _ in calls(function):
            name = external_name(module, call)
            if name in STDIN_READERS:
                stdin_evidence.append(f"{function.name} calls {name} at {call.origin.address:#x}")
    if stdin_evidence:
        candidates.append(InputCandidate(InputKind.STDIN, None, tuple(stdin_evidence)))
    return candidates


def _argv_uses(module: Module, main: Function) -> dict[int, set[str]]:
    argv_register = calling_convention(module.target).integer_parameters[1]
    uses: dict[int, set[str]] = {}
    seeds: dict[int, dict[str, set[_Tag]]] = {main.entry: {argv_register: {("array", 0)}}}
    work = [main.entry]
    while work:
        entry = work.pop()
        function = module.function_at(entry)
        if function is None:
            continue
        for callee, register, tags in _ArgvFlow(module, function, seeds[entry], uses).run():
            known = seeds.setdefault(callee, {}).setdefault(register, set())
            if not tags <= known:
                known |= tags
                work.append(callee)
    return uses


_MAX_PHI_DEPTH = 16


class _Addresses:
    """Base + offset forms of pointers, seen through phis and register-preserving calls.

    This is for gathering evidence only. It trusts the calling convention: registers a
    callee must preserve survive a call, and a call pops its return address. Simplification
    cannot assume that (a callee may break the convention), so it is not used there.
    """

    def __init__(self, module: Module, function: Function) -> None:
        convention = calling_convention(module.target)
        self.width = module.target.pointer_width
        self.steps: dict[int, tuple[Operand, int]] = {}
        self.phis: dict[int, Phi] = {}
        for block in function.blocks:
            for phi in block.phis:
                self.phis[phi.output.id] = phi
            for operation in block.operations:
                match operation:
                    case BinaryOp(
                        opcode=BinaryOpcode.ADD | BinaryOpcode.SUB, right=Const(value=delta)
                    ):
                        sign = 1 if operation.opcode is BinaryOpcode.ADD else -1
                        self.steps[operation.output.id] = (operation.left, sign * delta)
                    case Call():
                        self._call(operation, convention.stack_pointer, convention.clobbers)
                    case _:
                        pass
        self._cache: dict[int, CanonicalAddress] = {}

    def _call(self, call: Call, stack_pointer: str, clobbers: frozenset[str]) -> None:
        arguments = dict(zip(call.argument_registers, call.arguments, strict=True))
        for register, result in zip(call.result_registers, call.results, strict=True):
            argument = arguments.get(register)
            if argument is None:
                continue
            if register == stack_pointer:
                self.steps[result.id] = (argument, self.width // 8)
            elif register not in clobbers:
                self.steps[result.id] = (argument, 0)

    def preserved(self, result: Var) -> Operand | None:
        """The argument a call result equals under the calling convention, if any."""
        step = self.steps.get(result.id)
        return step[0] if step is not None and step[1] == 0 else None

    def resolve(self, operand: Operand) -> CanonicalAddress:
        if isinstance(operand, Var) and operand.id in self._cache:
            return self._cache[operand.id]
        found = self._resolve(operand, ())
        if isinstance(operand, Var):
            self._cache[operand.id] = found
        return found

    def _resolve(self, operand: Operand, active: tuple[int, ...]) -> CanonicalAddress:
        offset = 0
        current = operand
        while isinstance(current, Var) and current.id in self.steps:
            current, delta = self.steps[current.id]
            offset += delta
        if isinstance(current, Const):
            return CanonicalAddress(None, (current.value + offset) & mask(self.width))
        own = CanonicalAddress(current.id, offset & mask(self.width))
        phi = self.phis.get(current.id)
        if phi is None or current.id in active or len(active) >= _MAX_PHI_DEPTH:
            return own
        # A phi is a fixed address when every incoming value is that address, or the phi
        # itself unchanged (a loop that preserves it).
        unchanged = CanonicalAddress(current.id, 0)
        found = {self._resolve(value, (*active, current.id)) for _, value in phi.incoming}
        found.discard(unchanged)
        if len(found) != 1:
            return own
        base = found.pop()
        return CanonicalAddress(base.base, (base.offset + offset) & mask(self.width))


class _ArgvFlow:
    """Flow-insensitive propagation of argv provenance within one function."""

    def __init__(
        self,
        module: Module,
        function: Function,
        inputs: dict[str, set[_Tag]],
        uses: dict[int, set[str]],
    ) -> None:
        self.module = module
        self.function = function
        self.uses = uses
        self.pointer_size = module.target.pointer_width // 8
        self.values: dict[int, set[_Tag]] = {
            item.value.id: set(inputs[item.register])
            for item in function.inputs
            if item.register in inputs
        }
        self.slots: dict[CanonicalAddress, set[_Tag]] = {}
        self.addresses = _Addresses(module, function)

    def tags(self, operand: Operand) -> set[_Tag]:
        return set() if isinstance(operand, Const) else self.values.get(operand.id, set())

    def _flow(self, target: Var, found: set[_Tag]) -> bool:
        current = self.values.setdefault(target.id, set())
        if found <= current:
            return False
        current |= found
        return True

    def _record(self, found: set[_Tag], detail: str) -> None:
        for kind, index in found:
            if kind == "string":
                self.uses.setdefault(index, set()).add(detail)

    def _slot(self, address: Operand) -> CanonicalAddress:
        return self.addresses.resolve(address)

    def run(self) -> list[tuple[int, str, set[_Tag]]]:
        changed = True
        while changed:
            changed = False
            for block in self.function.blocks:
                for phi in block.phis:
                    for _, value in phi.incoming:
                        changed |= self._flow(phi.output, self.tags(value))
                for operation in block.operations:
                    match operation:
                        case BinaryOp(
                            opcode=BinaryOpcode.ADD | BinaryOpcode.SUB, right=Const(value=delta)
                        ):
                            if operation.opcode is BinaryOpcode.SUB:
                                delta = -delta
                            shifted: set[_Tag] = {
                                (kind, position + delta if kind == "array" else position)
                                for kind, position in self.tags(operation.left)
                            }
                            changed |= self._flow(operation.output, shifted)
                        case BinaryOp(opcode=BinaryOpcode.ADD, left=left, right=right):
                            # A string pointer plus a variable index still points into the
                            # string; an argv slot at an unknown index is not tracked.
                            indexed = {
                                tag
                                for tag in self.tags(left) | self.tags(right)
                                if tag[0] == "string"
                            }
                            changed |= self._flow(operation.output, indexed)
                        case Load(output=output, address=address):
                            address_tags = self.tags(address)
                            elements = {
                                ("string", offset // self.pointer_size)
                                for kind, offset in address_tags
                                if kind == "array" and offset % self.pointer_size == 0
                            }
                            where = operation.origin.address
                            self._record(
                                address_tags, f"{self.function.name} reads it at {where:#x}"
                            )
                            stored = self.slots.get(self._slot(address), set())
                            changed |= self._flow(output, elements | stored)
                        case Store(address=address, value=value) if self.tags(value):
                            slot = self.slots.setdefault(self._slot(address), set())
                            if not self.tags(value) <= slot:
                                slot |= self.tags(value)
                                changed = True
                        case Call(results=results):
                            for result in results:
                                argument = self.addresses.preserved(result)
                                if argument is not None:
                                    changed |= self._flow(result, self.tags(argument))
                        case _:
                            pass
        outgoing: list[tuple[int, str, set[_Tag]]] = []
        for call, _ in calls(self.function):
            name = external_name(self.module, call)
            for register, argument in zip(call.argument_registers, call.arguments, strict=True):
                found = self.tags(argument)
                if not found:
                    continue
                if name is not None:
                    where = call.origin.address
                    self._record(found, f"{self.function.name} passes it to {name} at {where:#x}")
                elif isinstance(call.target, DirectTarget):
                    outgoing.append((call.target.address, register, found))
        return outgoing

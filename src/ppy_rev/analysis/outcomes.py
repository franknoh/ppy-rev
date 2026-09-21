"""Outcomes a program reaches only because of what it was given.

A checker's success is not a word. Plenty of challenges answer in their own language, or
in none: they print the flag a character at a time, or a string they built while running,
and a list of English keywords sees nothing at all. What such an outcome *is*, in shape,
is an output the program reaches only after the input decided something — and usually one
it ends well from.

So this looks for that shape rather than for words:

    the call prints something
    it is control-dependent on a branch whose condition came from the input
    the program leaves with a success status from there, rather than a failure

Each of those is evidence the caller can read, and none of them needs the message to be
readable at all. It is a fallback: a program that does say `Correct!` is ranked on that,
because the words are better evidence than the shape when they are there.
"""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.abi import calling_convention
from ppy_rev.analysis.locations import Location, Locations, definitions
from ppy_rev.analysis.program import external_name
from ppy_rev.ir.cfg import ControlFlow, control_flow, immediate_post_dominators
from ppy_rev.ir.model import (
    BinaryOp,
    Block,
    Branch,
    Call,
    Const,
    DirectTarget,
    Function,
    Load,
    Module,
    Operand,
    Operation,
    Return,
    Store,
    Subpiece,
    UnaryOp,
    Var,
    operation_inputs,
    operation_output,
    successors,
)

READS_INTO = {
    "fgets": (0,),
    "gets": (0,),
    "read": (1,),
    "fread": (0,),
    "scanf": (1, 2, 3, 4, 5),
    "sscanf": (2, 3, 4, 5),
    "fscanf": (2, 3, 4, 5),
    "std::getline": (1,),
    "std::istream::operator>>": (1,),
    "std::istream::operator>>(short)": (1,),
    "std::istream::operator>>(int)": (1,),
    "std::istream::operator>>(long)": (1,),
}
"""Which argument of a reading function the input lands in."""
RETURNS_INPUT = frozenset({"getchar", "fgetc", "getc", "atoi", "atol", "atoll", "strtol"})
"""Reading functions whose result *is* the input rather than a place to put it."""
PRINTS = frozenset(
    {
        "puts",
        "putchar",
        "putc",
        "fputc",
        "fputs",
        "printf",
        "__printf_chk",
        "fprintf",
        "__fprintf_chk",
        "fwrite",
        "write",
        "std::ostream::operator<<",
        "std::endl",
    }
)
"""Everything a program prints through, including one character at a time.

Wider than the set a *string* can be passed to: a challenge that spells its answer out
with `putc` says just as much as one that calls `puts`, and says it the same way.
"""
_LEAVES = {"exit": None, "_exit": None, "abort": 1, "__stack_chk_fail": 1}
"""Calls that end the program, and the status they end with when it is not an argument."""


@dataclass(frozen=True, slots=True)
class OutputSite:
    """A call that prints, and what had to happen for the program to reach it."""

    function: str
    address: int
    call: str
    decisions: tuple[int, ...]
    """Branches on the input that decide whether this is reached."""
    prints_input: bool
    """What it prints came from the input: a program spelling out what it worked out."""
    ends_well: bool
    """Some way on from here leaves the program with a success status."""
    ends_badly: bool


def input_dependent_outputs(
    module: Module, functions: list[Function], printing: frozenset[str]
) -> list[OutputSite]:
    """Printing calls that the input decides the program reaches, in address order."""
    found: list[OutputSite] = []
    for function in functions:
        found.extend(_Outcomes(module, function, printing).run())
    return sorted(found, key=lambda site: site.address)


class _Outcomes:
    """Where the input reaches in one function, and what that decides."""

    def __init__(self, module: Module, function: Function, printing: frozenset[str]) -> None:
        self.module = module
        self.function = function
        self.printing = printing
        self.convention = calling_convention(module.target)
        self.locations = Locations(function, definitions(function))
        self.values: set[int] = set()
        """Values that came from the input."""
        self.memory: set[Location] = set()
        """Places the input was read into."""
        if function.name == "main":
            argv = self.convention.integer_parameters[1]
            for item in function.inputs:
                if item.register == argv:
                    self.values.add(item.value.id)

    # -- where the input reaches ---------------------------------------------------------

    def _spread(self) -> None:
        changed = True
        while changed:
            changed = False
            for block in self.function.blocks:
                for phi in block.phis:
                    if phi.output.id not in self.values and any(
                        self._tainted(value) for _, value in phi.incoming
                    ):
                        self.values.add(phi.output.id)
                        changed = True
                for operation in block.operations:
                    changed = self._step(operation) or changed

    def _step(self, operation: Operation) -> bool:
        match operation:
            case Call():
                return self._call(operation)
            case Store(address=address, value=value):
                if not self._tainted(value):
                    return False
                location = self.locations.of(address)
                if location in self.memory:
                    return False
                self.memory.add(location)
                return True
            case Load(output=output, address=address):
                if output.id in self.values:
                    return False
                if self.locations.of(address) not in self.memory and not self._tainted(address):
                    return False
                self.values.add(output.id)
                return True
            case BinaryOp() | UnaryOp() | Subpiece():
                return self._derived(operation)
            case _:
                return False

    def _derived(self, operation: Operation) -> bool:
        outputs = list(operation_output(operation))
        if not outputs or outputs[0].id in self.values:
            return False
        if not any(self._tainted(value) for value in operation_inputs(operation)):
            return False
        self.values.add(outputs[0].id)
        return True

    def _call(self, call: Call) -> bool:
        name = external_name(self.module, call) or ""
        arguments = dict(zip(call.argument_registers, call.arguments, strict=True))
        registers = self.convention.integer_parameters
        changed = False
        for index in READS_INTO.get(name, ()):
            if index >= len(registers):
                continue
            destination = arguments.get(registers[index])
            if destination is None:
                continue
            location = self.locations.of(destination)
            if location not in self.memory:
                self.memory.add(location)
                changed = True
        carries = any(self._tainted(value) for value in _parameters(call, registers))
        if name in RETURNS_INPUT or carries:
            # Only what the callee returns carries the input on: the other results are
            # registers it gave back untouched.
            for register in self.convention.integer_returns:
                if register not in call.result_registers:
                    continue
                result = call.results[call.result_registers.index(register)]
                if result.id not in self.values:
                    self.values.add(result.id)
                    changed = True
        if carries and call.arguments:
            # A call handed the input writes it somewhere: `strcpy(there, input)`.
            first = arguments.get(registers[0])
            if first is not None:
                location = self.locations.of(first)
                if location not in self.memory:
                    self.memory.add(location)
                    changed = True
        return changed

    def _tainted(self, value: Operand) -> bool:
        return isinstance(value, Var) and value.id in self.values

    # -- what the input decides ----------------------------------------------------------

    def run(self) -> list[OutputSite]:
        self._spread()
        decisions = {
            block.id: block.terminator.origin.address
            for block in self.function.blocks
            if isinstance(block.terminator, Branch) and self._tainted(block.terminator.condition)
        }
        if not decisions:
            return []
        flow = control_flow(self.function)
        post = immediate_post_dominators(self.function)
        depends = _control_dependence(flow, post)
        statuses = self._exit_statuses()
        found: list[OutputSite] = []
        for block in self.function.blocks:
            deciding = tuple(
                sorted(decisions[other] for other in depends[block.id] if other in decisions)
            )
            # A call every run makes says nothing about the input, however it got its
            # argument: a banner, or a program reading back what it was given.
            always = _post_dominates(post, block.id, 0)
            well, badly = statuses[block.id]
            for operation in block.operations:
                name = self._printer(operation)
                if name is None or not isinstance(operation, Call):
                    continue
                shows = self._shows_input(operation)
                if not deciding and not (shows and not always):
                    continue
                found.append(
                    OutputSite(
                        function=self.function.name,
                        address=operation.origin.address,
                        call=name,
                        decisions=deciding,
                        prints_input=shows,
                        ends_well=well,
                        ends_badly=badly,
                    )
                )
        return found

    def _shows_input(self, call: Call) -> bool:
        """Whether what this prints came from the input, by value or through a buffer.

        Only the registers a callee takes its arguments in: every call carries the rest
        of the machine along with it, and the input is usually somewhere in there.
        """
        return any(
            self._tainted(argument) or self.locations.of(argument) in self.memory
            for argument in _parameters(call, self.convention.integer_parameters)
        )

    def _printer(self, operation: Operation) -> str | None:
        """The name of what this operation prints through, when it prints."""
        if not isinstance(operation, Call):
            return None
        name = external_name(self.module, operation)
        if name is None and isinstance(operation.target, DirectTarget):
            callee = self.module.function_at(operation.target.address)
            name = None if callee is None else callee.name
        if name is None:
            return None
        return name if name in PRINTS or name in self.printing else None

    # -- how the program ends ------------------------------------------------------------

    def _exit_statuses(self) -> list[tuple[bool, bool]]:
        """For each block, whether the ways on from it end well, badly, or both."""
        good: set[int] = set()
        bad: set[int] = set()
        for block in self.function.blocks:
            status = self._status_of(block)
            if status is not None:
                (good if status == 0 else bad).add(block.id)
        result: list[tuple[bool, bool]] = []
        for block in self.function.blocks:
            reached = _reachable_from(self.function, block.id)
            result.append((bool(reached & good), bool(reached & bad)))
        return result

    def _status_of(self, block: Block) -> int | None:
        """The status the program leaves with here, when this block is where it ends."""
        for operation in block.operations:
            if not isinstance(operation, Call):
                continue
            name = external_name(self.module, operation)
            if name not in _LEAVES:
                continue
            settled = _LEAVES[name]
            if settled is not None:
                return settled
            arguments = dict(zip(operation.argument_registers, operation.arguments, strict=True))
            value = arguments.get(self.convention.integer_parameters[0])
            return value.value & 0xFF if isinstance(value, Const) else None
        if isinstance(block.terminator, Return) and self.function.name == "main":
            registers = list(self.function.output_registers)
            returned = self.convention.integer_returns[0]
            if returned in registers and registers.index(returned) < len(block.terminator.values):
                value = block.terminator.values[registers.index(returned)]
                return value.value & 0xFF if isinstance(value, Const) else None
        return None


def _reachable_from(function: Function, start: int) -> set[int]:
    seen = {start}
    work = [start]
    while work:
        for target in successors(function.blocks[work.pop()].terminator):
            if target not in seen:
                seen.add(target)
                work.append(target)
    return seen


def _control_dependence(flow: ControlFlow, post: tuple[int | None, ...]) -> list[set[int]]:
    """Which branches decide whether each block runs.

    A block depends on a branch when one way out of it always leads here and the branch
    itself does not: the usual definition, walked over the post-dominator tree.
    """
    depends: list[set[int]] = [set() for _ in flow.successors]
    for decision, targets in enumerate(flow.successors):
        if len(targets) < 2:
            continue
        for target in targets:
            current: int | None = target
            while current is not None and current != decision:
                if not _post_dominates(post, current, decision):
                    depends[current].add(decision)
                current = post[current]
    return depends


def _post_dominates(post: tuple[int | None, ...], block: int, of: int) -> bool:
    current: int | None = of
    while current is not None:
        if current == block:
            return True
        current = post[current]
    return False


def _parameters(call: Call, registers: tuple[str, ...]) -> list[Operand]:
    """The values a callee reads as its arguments, in order."""
    passed = dict(zip(call.argument_registers, call.arguments, strict=True))
    return [passed[register] for register in registers if register in passed]

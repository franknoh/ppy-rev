"""Outcomes a program reaches only because of what it was given.

A checker's success is not a word. Plenty of challenges answer in their own language, or
in none: they print the flag a character at a time, or a string they built while running,
and a list of English keywords sees nothing at all. What such an outcome *is*, in shape,
is an output the program reaches only after the input decided something — and usually one
it ends well from.

So this looks for that shape rather than for words:

    the call prints something, or the program leaves with a success status
    it is control-dependent on a branch whose condition came from the input
    the ways on from it do not end in failure

The input is followed across calls, because a checker is usually handed the buffer and
decides inside; and through a call table, because a program that dispatches that way
prints that way too.

Each of those is evidence the caller can read, and none of them needs the message to be
readable at all. It is a fallback: a program that does say `Correct!` is ranked on that,
because the words are better evidence than the shape when they are there.
"""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.abi import calling_convention
from ppy_rev.analysis.locations import Location, Locations, definitions
from ppy_rev.analysis.program import callee_addresses, external_name
from ppy_rev.ir.cfg import ControlFlow, control_flow, immediate_post_dominators
from ppy_rev.ir.model import (
    BinaryOp,
    Block,
    Branch,
    Call,
    Const,
    Function,
    Load,
    Module,
    Operand,
    Operation,
    Phi,
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
    """Printing calls that the input decides the program reaches, in address order.

    The input does not stop at the function that read it: a checker is handed the buffer
    and decides there, so what a call carries is followed into the callee until nothing
    new arrives.
    """
    by_entry = {function.entry: function for function in functions}
    start = functions[0].entry if functions else 0
    """Where the program starts: the one whose return value is the program's status."""
    seeded: dict[int, frozenset[str]] = {function.entry: frozenset() for function in functions}
    analyses: dict[int, _Outcomes] = {}
    work = [function.entry for function in functions]
    while work:
        entry = work.pop()
        function = by_entry.get(entry)
        if function is None:
            continue
        outcomes = _Outcomes(module, function, printing, seeded[entry], entry == start)
        outcomes.spread()
        analyses[entry] = outcomes
        for callee, carried in outcomes.carried():
            if callee not in seeded:
                continue
            grown = seeded[callee] | carried
            if grown != seeded[callee]:
                seeded[callee] = grown
                work.append(callee)
    found: list[OutputSite] = []
    for entry, outcomes in analyses.items():
        del entry
        found.extend(outcomes.sites())
    return sorted(found, key=lambda site: site.address)


class _Outcomes:
    """Where the input reaches in one function, and what that decides."""

    def __init__(
        self,
        module: Module,
        function: Function,
        printing: frozenset[str],
        seeded: frozenset[str] = frozenset(),
        entry: bool = False,
    ) -> None:
        self.module = module
        self.function = function
        self.printing = printing
        self.convention = calling_convention(module.target)
        self.locations = Locations(function, definitions(function))
        self.values: set[int] = set()
        """Values that came from the input."""
        self.memory: set[Location] = set()
        """Places the input was read into."""
        self._leaving_cache: dict[int, tuple[int, int, str]] | None = None
        self.entry = entry
        """Whether this is where the program starts: its return value is the status."""
        carried = set(seeded)
        if entry:
            carried.add(self.convention.integer_parameters[1])
        for item in function.inputs:
            if item.register in carried:
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
        # Handing over a pointer to where the input was read hands over the input: a
        # checker is usually `check(buffer)`, and the buffer's address is its own value.
        carries = any(self._carries(value) for value in _parameters(call, registers))
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

    def _carries(self, value: Operand) -> bool:
        """Whether a value is the input, or points at where the input was read."""
        return self._tainted(value) or self.locations.of(value) in self.memory

    # -- what the input decides ----------------------------------------------------------

    def carried(self) -> list[tuple[int, frozenset[str]]]:
        """For each call, where it can go and which of its arguments carry the input."""
        registers = self.convention.integer_parameters
        found: list[tuple[int, frozenset[str]]] = []
        for block in self.function.blocks:
            for operation in block.operations:
                if not isinstance(operation, Call):
                    continue
                passed = dict(zip(operation.argument_registers, operation.arguments, strict=True))
                carrying = frozenset(
                    register
                    for register in registers
                    if register in passed and self._carries(passed[register])
                )
                if not carrying:
                    continue
                found.extend((address, carrying) for address in callee_addresses(operation.target))
        return found

    def spread(self) -> None:
        """Follow the input through this function's values and memory."""
        self._spread()

    def run(self) -> list[OutputSite]:
        self._spread()
        return self.sites()

    def sites(self) -> list[OutputSite]:
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
            leaving = self.leaving().get(block.id) if deciding else None
            if leaving is not None and leaving[0] == 0:
                # Plenty of checkers say nothing at all: passing is leaving with zero.
                found.append(
                    OutputSite(
                        function=self.function.name,
                        address=leaving[1],
                        call=leaving[2],
                        decisions=deciding,
                        prints_input=False,
                        ends_well=True,
                        ends_badly=False,
                    )
                )
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
            self._carries(argument)
            for argument in _parameters(call, self.convention.integer_parameters)
        )

    def _printer(self, operation: Operation) -> str | None:
        """The name of what this operation prints through, when it prints."""
        if not isinstance(operation, Call):
            return None
        name = external_name(self.module, operation)
        if name is not None:
            return name if name in PRINTS or name in self.printing else None
        # A program that dispatches through a table calls its printer that way too.
        for address in callee_addresses(operation.target):
            callee = self.module.function_at(address)
            if callee is not None and (callee.name in PRINTS or callee.name in self.printing):
                return callee.name
        return None

    # -- how the program ends ------------------------------------------------------------

    def _exit_statuses(self) -> list[tuple[bool, bool]]:
        """For each block, whether the ways on from it end well, badly, or both."""
        good: set[int] = set()
        bad: set[int] = set()
        for block_id, (status, _, _) in self.leaving().items():
            (good if status == 0 else bad).add(block_id)
        result: list[tuple[bool, bool]] = []
        for block in self.function.blocks:
            reached = _reachable_from(self.function, block.id)
            result.append((bool(reached & good), bool(reached & bad)))
        return result

    def leaving(self) -> dict[int, tuple[int, int, str]]:
        """Blocks the program leaves from, with the status and what it leaves by.

        A status the program *chooses* in one block and returns from another counts for
        the block that chose it: `main` usually sets 0 or 1 and returns once.
        """
        if self._leaving_cache is not None:
            return self._leaving_cache
        found: dict[int, tuple[int, int, str]] = {}
        for block in self.function.blocks:
            item = self._leaving(block)
            if item is not None:
                found[block.id] = item
        for block in self.function.blocks:
            for chooser, status in self._chosen_status(block):
                found.setdefault(
                    chooser,
                    (status, self.function.blocks[chooser].terminator.origin.address, "return"),
                )
        self._leaving_cache = found
        return found

    def _chosen_status(self, block: Block) -> list[tuple[int, int]]:
        """(block, status) for a return of a value that earlier blocks picked between."""
        terminator = block.terminator
        if not isinstance(terminator, Return) or not self.entry:
            return []
        registers = list(self.function.output_registers)
        returned = self.convention.integer_returns[0]
        if returned not in registers or registers.index(returned) >= len(terminator.values):
            return []
        value = terminator.values[registers.index(returned)]
        if not isinstance(value, Var):
            return []
        phi = self.locations.definitions.get(value.id)
        if not isinstance(phi, Phi):
            return []
        return [
            (predecessor, incoming.value & 0xFF)
            for predecessor, incoming in phi.incoming
            if isinstance(incoming, Const)
        ]

    def _leaving(self, block: Block) -> tuple[int, int, str] | None:
        """The status the program leaves with here, where it does, and what it leaves by."""
        for operation in block.operations:
            if not isinstance(operation, Call):
                continue
            name = external_name(self.module, operation)
            if name not in _LEAVES:
                continue
            settled = _LEAVES[name]
            if settled is not None:
                return (settled, operation.origin.address, name or "exit")
            arguments = dict(zip(operation.argument_registers, operation.arguments, strict=True))
            value = arguments.get(self.convention.integer_parameters[0])
            if not isinstance(value, Const):
                return None
            return (value.value & 0xFF, operation.origin.address, name or "exit")
        if isinstance(block.terminator, Return) and self.entry:
            registers = list(self.function.output_registers)
            returned = self.convention.integer_returns[0]
            if returned in registers and registers.index(returned) < len(block.terminator.values):
                value = block.terminator.values[registers.index(returned)]
                if isinstance(value, Const):
                    return (value.value & 0xFF, block.terminator.origin.address, "return")
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

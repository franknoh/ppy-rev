"""Ghidra export → RevIR module."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from ppy_rev.diagnostics import Diagnostic, UnsupportedBinaryError
from ppy_rev.ghidra.schema import Function as GhidraFunction
from ppy_rev.ghidra.schema import GhidraExport, Instruction
from ppy_rev.ir.model import (
    CallTarget,
    DirectTarget,
    Endianness,
    ExternalFunction,
    ExternalTarget,
    Function,
    Label,
    MemoryRegion,
    Module,
    Register,
    Target,
)
from ppy_rev.lift.cfg import ProgramView, recover_cfg
from ppy_rev.lift.ssa import FunctionBuilder, FunctionContext
from ppy_rev.lift.storage import StoragePartition, partition, register_names

_ARCHITECTURES = {"x86:LE:64": "x86-64"}


@dataclass(frozen=True, slots=True)
class LiftResult:
    module: Module
    diagnostics: tuple[Diagnostic, ...]


def lift_export(export: GhidraExport, functions: frozenset[str] | None = None) -> LiftResult:
    """Lift every internal function (or only those named in `functions`)."""
    binary = export.binary
    if binary.endianness != "little":
        raise UnsupportedBinaryError(f"{binary.language}: only little-endian targets are supported")
    architecture = next(
        (name for prefix, name in _ARCHITECTURES.items() if binary.language.startswith(prefix)),
        binary.language,
    )
    target = Target(
        architecture=architecture,
        endianness=Endianness.LITTLE,
        pointer_width=binary.pointer_size * 8,
        stack_pointer=binary.stack_pointer,
        program_counter=binary.program_counter,
    )
    registers = _register_partition(export)

    callable_entries = {function.entry for function in export.functions}
    thunks = {f.entry: f.thunk_target for f in export.functions if f.thunk_target is not None}
    external_no_return = {f.name: f.no_return for f in export.external_functions}
    external_symbols = {
        f.name: f.original_name for f in export.external_functions if f.original_name
    }

    def resolve_call(address: int) -> CallTarget:
        thunk = thunks.get(address)
        if thunk is None:
            return DirectTarget(address)
        if thunk.external:
            return ExternalTarget(thunk.name, address)
        return DirectTarget(thunk.address)

    no_return = frozenset(
        function.entry
        for function in export.functions
        if function.no_return
        or (
            function.thunk_target is not None
            and function.thunk_target.external
            and external_no_return.get(function.thunk_target.name, False)
        )
    )
    instructions = {instruction.address: instruction for instruction in export.instructions}
    view = ProgramView(
        instructions=instructions,
        function_entries=frozenset(callable_entries),
        no_return_targets=no_return,
    )
    diagnostics: list[Diagnostic] = []
    lifted: list[Function] = []
    for function in sorted(export.functions, key=lambda function: function.entry):
        if not _liftable(function, instructions, functions):
            continue
        cfg = recover_cfg(view, function.entry)
        context = FunctionContext(
            name=function.name,
            registers=registers,
            register_order=registers.groups,
            pointer_width=target.pointer_width,
            instructions=instructions,
            resolve_call=resolve_call,
        )
        builder = FunctionBuilder(context, cfg)
        lifted.append(builder.build())
        diagnostics.extend(builder.diagnostics)

    externals: dict[str, list[int]] = {}
    for function in export.functions:
        if function.thunk_target is not None and function.thunk_target.external:
            externals.setdefault(function.thunk_target.name, []).append(function.entry)
    module = Module(
        name=binary.name,
        target=target,
        registers=tuple(
            Register(group.name, group.offset, group.size * 8) for group in registers.groups
        ),
        memory=tuple(
            MemoryRegion(
                name=block.name,
                start=block.start,
                size=block.size,
                readable=block.read,
                writable=block.write,
                executable=block.execute,
                data=block.data,
            )
            for block in export.memory_blocks
            if block.loaded and not block.artificial and block.space == "ram"
        ),
        externals=tuple(
            ExternalFunction(
                name,
                tuple(sorted(addresses)),
                external_no_return.get(name, False),
                external_symbols.get(name, ""),
            )
            for name, addresses in sorted(externals.items())
        ),
        functions=tuple(lifted),
        labels=tuple(
            Label(symbol.address, symbol.name)
            for symbol in export.symbols
            if symbol.address is not None and symbol.primary and not symbol.external
        ),
    )
    return LiftResult(module, tuple(diagnostics))


def _liftable(
    function: GhidraFunction,
    instructions: Mapping[int, Instruction],
    selected: frozenset[str] | None,
) -> bool:
    if function.thunk_target is not None or function.entry not in instructions:
        return False
    return selected is None or function.name in selected


def _register_partition(export: GhidraExport) -> StoragePartition:
    """Group every register the program touches, widened to its whole base register.

    Widening keeps ABI-level views intact: a program that only uses EDI still gets an RDI
    variable, so a callee or library summary reading the full register sees all its bits.
    """
    names = register_names(export.registers)
    by_name = {register.name: register for register in export.registers}
    ranges: list[tuple[int, int]] = []

    def add(offset: int, size: int) -> None:
        name = names.get((offset, size))
        base = by_name.get(by_name[name].base) if name is not None else None
        ranges.append((offset, size) if base is None else (base.offset, base.size))

    for instruction in export.instructions:
        for op in instruction.pcode:
            for varnode in (*op.inputs, *(() if op.output is None else (op.output,))):
                if varnode.space == "register":
                    add(varnode.offset, varnode.size)
    for special in (export.binary.stack_pointer, export.binary.program_counter):
        add(by_name[special].offset, by_name[special].size)
    return partition(ranges, names, "register")

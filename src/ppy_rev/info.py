"""Summary of a program's static structure, as reported by `ppy-rev info`."""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.elf import ElfHeader
from ppy_rev.ghidra.schema import GhidraExport


@dataclass(frozen=True, slots=True)
class SectionInfo:
    name: str
    start: int
    size: int
    permissions: str


@dataclass(frozen=True, slots=True)
class FunctionInfo:
    name: str
    entry: int
    thunk_of: str | None


@dataclass(frozen=True, slots=True)
class ProgramInfo:
    name: str
    sha256: str | None
    format: str
    architecture: str
    bits: int
    endianness: str
    elf_type: str
    ghidra_language: str
    compiler: str
    image_base: int
    entry: int
    entry_symbol: str | None
    sections: tuple[SectionInfo, ...]
    functions: tuple[FunctionInfo, ...]
    imports: tuple[str, ...]


def program_info(export: GhidraExport, header: ElfHeader) -> ProgramInfo:
    binary = export.binary
    entry = header.rebase(header.entry, binary.image_base)
    names = {
        symbol.address: symbol.name
        for symbol in export.symbols
        if symbol.address is not None and symbol.primary
    }
    sections = tuple(
        SectionInfo(
            name=block.name,
            start=block.start,
            size=block.size,
            permissions=("r" if block.read else "-")
            + ("w" if block.write else "-")
            + ("x" if block.execute else "-"),
        )
        for block in export.memory_blocks
        if block.loaded and not block.artificial
    )
    functions = tuple(
        FunctionInfo(
            name=function.name,
            entry=function.entry,
            thunk_of=None if function.thunk_target is None else function.thunk_target.name,
        )
        for function in export.functions
        if not _is_external_placeholder(export, function.entry)
    )
    return ProgramInfo(
        name=binary.name,
        sha256=binary.sha256,
        format="ELF",
        architecture=header.machine_name,
        bits=header.bits,
        endianness=header.endianness,
        elf_type=header.type_name,
        ghidra_language=binary.language,
        compiler=binary.compiler_spec,
        image_base=binary.image_base,
        entry=entry,
        entry_symbol=names.get(entry),
        sections=sections,
        functions=functions,
        imports=tuple(sorted({external.name for external in export.external_functions})),
    )


def _is_external_placeholder(export: GhidraExport, address: int) -> bool:
    """Ghidra gives each import a placeholder function inside the artificial EXTERNAL block."""
    return any(
        block.external and block.start <= address < block.end for block in export.memory_blocks
    )

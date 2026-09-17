"""The public library entry point."""

from __future__ import annotations

from pathlib import Path

from ppy_rev.config import AnalyzerConfig
from ppy_rev.elf import read_elf_header
from ppy_rev.ghidra.frontend import export_binary
from ppy_rev.ghidra.schema import GhidraExport
from ppy_rev.info import ProgramInfo, program_info


class Analyzer:
    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self.config = config if config is not None else AnalyzerConfig()

    def export(self, binary: Path) -> GhidraExport:
        """Run (or reuse a cached) Ghidra analysis and return the validated export."""
        return export_binary(binary, self.config)

    def info(self, binary: Path) -> ProgramInfo:
        return program_info(self.export(binary), read_elf_header(binary))

"""The public library entry point."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ppy_rev.abi import calling_convention
from ppy_rev.config import AnalyzerConfig
from ppy_rev.elf import read_elf_header
from ppy_rev.ghidra.frontend import export_binary
from ppy_rev.ghidra.schema import GhidraExport
from ppy_rev.info import ProgramInfo, program_info
from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import LiftResult, lift_export
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.solve import SolveRequest, SolveResult, solve_module
from ppy_rev.summaries.libc import modeled_reads


class Analyzer:
    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self.config = config if config is not None else AnalyzerConfig()

    def export(self, binary: Path) -> GhidraExport:
        """Run (or reuse a cached) Ghidra analysis and return the validated export."""
        return export_binary(binary, self.config)

    def info(self, binary: Path) -> ProgramInfo:
        return program_info(self.export(binary), read_elf_header(binary))

    def lift(self, binary: Path) -> LiftResult:
        """Lift every function Ghidra recovered into RevIR, exactly as p-code describes it."""
        return lift_export(self.export(binary))

    def simplify(self, lifted: LiftResult) -> LiftResult:
        """Simplify a lifted module, using what ppy-rev knows about library functions."""
        module = lifted.module
        reads = modeled_reads(calling_convention(module.target))
        return replace(lifted, module=simplify_module(module, reads))

    def simplified(self, binary: Path) -> Module:
        return self.simplify(self.lift(binary)).module

    def solve(self, request: SolveRequest) -> SolveResult:
        """Find inputs that drive the program to its success outcome."""
        return solve_module(self.simplified(request.binary), request)

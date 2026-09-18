"""The public library entry point."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ppy_rev.abi import calling_convention
from ppy_rev.analysis.report import AnalysisReport, analyze_module
from ppy_rev.config import AnalyzerConfig
from ppy_rev.elf import read_elf_header
from ppy_rev.ghidra.cache import ExportCache
from ppy_rev.ghidra.frontend import export_binary
from ppy_rev.ghidra.schema import GhidraExport
from ppy_rev.info import ProgramInfo, program_info
from ppy_rev.ir.model import Module
from ppy_rev.lift.lifter import LiftResult, lift_export
from ppy_rev.progress import Progress, Silent
from ppy_rev.simplify.pipeline import simplify_module
from ppy_rev.solve import SolveRequest, SolveResult, solve_module
from ppy_rev.summaries.libc import modeled_reads


class Analyzer:
    def __init__(
        self, config: AnalyzerConfig | None = None, progress: Progress | None = None
    ) -> None:
        self.config = config if config is not None else AnalyzerConfig()
        self.progress = progress if progress is not None else Silent()
        """Where long phases report what they are doing; silent unless asked."""

    def clear_cache(self) -> int:
        """Delete every cached Ghidra export; returns how many were removed."""
        return ExportCache(self.config.cache.resolve_directory()).clear()

    def export(self, binary: Path) -> GhidraExport:
        """Run (or reuse a cached) Ghidra analysis and return the validated export."""
        return export_binary(binary, self.config, self.progress)

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

    def analyze(self, binary: Path) -> AnalysisReport:
        """What solving would work with: inputs, likely outcomes, relevant code, VMs."""
        lifted = self.simplify(self.lift(binary))
        return analyze_module(lifted.module, lifted.diagnostics)

    def solve(self, request: SolveRequest) -> SolveResult:
        """Find inputs that drive the program to its success outcome."""
        return solve_module(self.simplified(request.binary), request, progress=self.progress)

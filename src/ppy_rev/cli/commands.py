"""Command handlers: parse arguments into requests, call the library, render results."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import TextIO

from ppy_rev.api import Analyzer
from ppy_rev.cli.render import (
    render_dispatchers,
    render_info,
    render_lifted_vm,
    render_solve,
    solution_bytes,
)
from ppy_rev.config import AnalyzerConfig, CacheOptions, GhidraOptions
from ppy_rev.diagnostics import PpyRevError, Severity
from ppy_rev.ir.text import format_module
from ppy_rev.ppy.check import check_ppy
from ppy_rev.ppy.emit import emit_module
from ppy_rev.solve import (
    SolveRequest,
    SolveResult,
    SolveStatus,
    Strategy,
    solve_module,
    verify_on,
)
from ppy_rev.symbolic.executor import Budget
from ppy_rev.symbolic.inputs import Charset
from ppy_rev.verify.sandbox import SandboxOptions
from ppy_rev.vm.detect import LIKELY_DISPATCHER, detect_dispatchers
from ppy_rev.vm.lift import isa_description, lift_vm, patch_interpreter

EXIT_ERROR = 1
EXIT_UNSOLVED = 2


def verbosity(arguments: argparse.Namespace) -> int:
    verbose: int = getattr(arguments, "verbose", 0)
    return verbose


def analyzer(arguments: argparse.Namespace) -> Analyzer:
    ghidra_home: Path | None = arguments.ghidra_home
    cache_dir: Path | None = arguments.cache_dir
    no_cache: bool = arguments.no_cache
    return Analyzer(
        AnalyzerConfig(
            ghidra=GhidraOptions(home=ghidra_home),
            cache=CacheOptions(enabled=not no_cache, directory=cache_dir),
        )
    )


def info(arguments: argparse.Namespace, out: TextIO) -> int:
    binary: Path = arguments.binary
    render_info(analyzer(arguments).info(binary), out)
    return 0


def lift(arguments: argparse.Namespace, out: TextIO) -> int:
    binary: Path = arguments.binary
    output: Path | None = arguments.output
    selected: list[str] | None = arguments.function
    no_simplify: bool = arguments.no_simplify
    emit_ppy: bool = arguments.emit_ppy
    emit_ir: bool = arguments.emit_ir
    check: bool = arguments.check_ppy
    tool = analyzer(arguments)
    lifted = tool.lift(binary)
    module = lifted.module if no_simplify else tool.simplify(lifted).module
    if selected:
        missing = sorted(set(selected) - {function.name for function in module.functions})
        if missing:
            raise PpyRevError(f"no lifted function named {', '.join(missing)}")
        module = replace(
            module, functions=tuple(f for f in module.functions if f.name in set(selected))
        )
    for diagnostic in lifted.diagnostics:
        if verbosity(arguments) > 0 or diagnostic.severity == Severity.ERROR:
            sys.stderr.write(diagnostic.render() + "\n")
    if emit_ppy:
        directory = output or Path("out")
        emitted = emit_module(module)
        emitted.write(directory)
        out.write(f"wrote PPy for {len(emitted.functions)} functions to {directory}\n")
        if not check:
            return 0
        result = check_ppy(directory)
        for line in (*result.errors, *result.checked_conversions):
            out.write(f"  {line}\n")
        out.write("ppy check: " + ("passed\n" if result.ok else "failed\n"))
        return 0 if result.ok else EXIT_ERROR
    if emit_ir:
        text = format_module(module)
        if output is None:
            out.write(text)
        else:
            output.write_text(text, encoding="utf-8")
        return 0
    operations = sum(len(block.operations) for f in module.functions for block in f.blocks)
    blocks = sum(len(function.blocks) for function in module.functions)
    out.write(
        f"lifted {len(module.functions)} functions: {blocks} blocks, {operations} operations, "
        f"{len(lifted.diagnostics)} diagnostics\n"
    )
    return 0


def _solve_request(arguments: argparse.Namespace) -> SolveRequest:
    binary: Path = arguments.binary
    charset: str | None = arguments.charset
    prefix: str | None = arguments.prefix
    goal_address: int | None = arguments.goal_address
    avoid_address: list[int] | None = arguments.avoid_address
    avoid_string: list[str] | None = arguments.avoid_string
    timeout: float = arguments.timeout
    max_states: int = arguments.max_states
    verify: bool = arguments.verify
    sandbox_runtime: Path | None = arguments.sandbox_runtime
    sandbox_image: str = arguments.sandbox_image
    strategy: str = arguments.strategy
    seed: str | None = arguments.seed
    return SolveRequest(
        binary=binary,
        argv=arguments.argv,
        stdin=arguments.stdin,
        goal_address=goal_address,
        goal_string=arguments.goal_string,
        avoid_addresses=tuple(avoid_address or ()),
        avoid_strings=tuple(avoid_string or ()),
        length=arguments.length,
        max_length=arguments.max_length,
        prefix=b"" if prefix is None else prefix.encode("latin-1"),
        charset=None if charset is None else Charset(charset),
        solutions=arguments.solutions,
        budget=Budget(
            max_seconds=timeout,
            solver_timeout_ms=int(min(timeout, 600) * 1000),
            max_states=max_states,
        ),
        emit_smt2=arguments.emit_smt2,
        native=SandboxOptions(runtime=sandbox_runtime, image=sandbox_image) if verify else None,
        strategy=Strategy(strategy),
        seed=None if seed is None else seed.encode("latin-1"),
    )


def solve(arguments: argparse.Namespace, out: TextIO) -> int:
    request = _solve_request(arguments)
    result = analyzer(arguments).solve(request)
    return _report_solution(arguments, result, out)


def _report_solution(arguments: argparse.Namespace, result: SolveResult, out: TextIO) -> int:
    output: Path | None = arguments.output
    render_solve(result, out, verbosity(arguments))
    if output is not None and result.solutions:
        output.write_bytes(solution_bytes(result.solutions[0]))
    return 0 if result.status is SolveStatus.SAT else EXIT_UNSOLVED


def vm_detect(arguments: argparse.Namespace, out: TextIO) -> int:
    binary: Path = arguments.binary
    show_all: bool = arguments.all
    tool = analyzer(arguments)
    module = tool.simplified(binary)
    candidates = detect_dispatchers(module)
    likely = [item for item in candidates if item.confidence >= LIKELY_DISPATCHER]
    render_dispatchers(
        f"{module.target.architecture} Linux ELF",
        candidates if show_all else likely,
        len(candidates) - len(likely),
        out,
    )
    return 0 if likely else EXIT_UNSOLVED


def vm_lift(arguments: argparse.Namespace, out: TextIO) -> int:
    binary: Path = arguments.binary
    emit_ir: bool = arguments.emit_ir
    json_path: Path | None = arguments.json
    module = analyzer(arguments).simplified(binary)
    lifted = lift_vm(module, SolveRequest(binary=binary))
    if emit_ir:
        out.write(format_module(replace(module, functions=(lifted.function,))))
    else:
        render_lifted_vm(f"{module.target.architecture} Linux ELF", lifted, out)
    if json_path is not None:
        json_path.write_text(json.dumps(isa_description(lifted), indent=2) + "\n", encoding="utf-8")
    return 0


def vm_solve(arguments: argparse.Namespace, out: TextIO) -> int:
    request = _solve_request(arguments)
    tool = analyzer(arguments)
    module = tool.simplified(request.binary)
    lifted = lift_vm(module, request)
    result = verify_on(module, solve_module(patch_interpreter(module, lifted), request))
    notes = (
        f"solved over {len(lifted.instructions)} lifted bytecode instructions instead of the "
        f"interpreter {lifted.dispatcher.function}; verified on the original interpreter",
        *result.notes,
    )
    return _report_solution(arguments, replace(result, notes=notes), out)

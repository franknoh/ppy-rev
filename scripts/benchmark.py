"""Time each stage of solving the fixture corpus, and record what each stage worked on.

    uv run python scripts/benchmark.py
    uv run python scripts/benchmark.py --fixtures xor_check,class_count --variants gcc-O2
    uv run python scripts/benchmark.py --fresh --json benchmark.json

Stages are measured separately: Ghidra (import, analysis, and export in one headless run;
cached unless --fresh), RevIR construction, simplification, backward slicing, symbolic
exploration, and SMT solving. Needs PPY_REV_GHIDRA_HOME and the fixture compilers.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from fixtures.compile import BUILD_ROOT, Variant, build, fixture_names  # noqa: E402
from ppy_rev import Analyzer, AnalyzerConfig, CacheOptions, SolveRequest  # noqa: E402
from ppy_rev.analysis.goals import rank_goals  # noqa: E402
from ppy_rev.analysis.program import (  # noqa: E402
    find_main,
    reachable_functions,
    string_references,
)
from ppy_rev.analysis.slicing import backward_slice  # noqa: E402
from ppy_rev.diagnostics import PpyRevError  # noqa: E402
from ppy_rev.lift.lifter import lift_export  # noqa: E402
from ppy_rev.solve import solve_module  # noqa: E402
from ppy_rev.symbolic.executor import Budget  # noqa: E402

SKIPPED = frozenset({"arith_ops", "libc_probe", "sandbox_probe"})
"""Fixtures that are not challenges."""


@dataclass(frozen=True, slots=True)
class Record:
    fixture: str
    variant: str
    status: str
    ghidra_seconds: float
    lift_seconds: float
    simplify_seconds: float
    slice_seconds: float
    exploration_seconds: float
    solver_seconds: float
    total_seconds: float
    functions: int
    blocks: int
    operations: int
    sliced_operations: int
    symbolic_branches: int
    path_constraints: int
    solver_calls: int
    peak_states: int


def measure(analyzer: Analyzer, name: str, variant: Variant, timeout: float) -> Record:
    binary = build(name, variant)
    started = time.monotonic()
    export = analyzer.export(binary)
    ghidra = time.monotonic()
    lifted = lift_export(export)
    lifting = time.monotonic()
    module = analyzer.simplify(lifted).module
    simplifying = time.monotonic()
    main = find_main(module)
    ranked = rank_goals(string_references(module, reachable_functions(module, main)))
    backward_slice(module, frozenset(item.address for item in ranked), main.entry)
    slicing = time.monotonic()
    result = solve_module(module, SolveRequest(binary=binary, budget=Budget(max_seconds=timeout)))
    finished = time.monotonic()
    statistics = result.statistics
    solving = finished - slicing
    return Record(
        fixture=name,
        variant=variant.label,
        status=str(result.status),
        ghidra_seconds=ghidra - started,
        lift_seconds=lifting - ghidra,
        simplify_seconds=simplifying - lifting,
        slice_seconds=slicing - simplifying,
        exploration_seconds=max(0.0, solving - statistics.solver_seconds),
        solver_seconds=statistics.solver_seconds,
        total_seconds=finished - started,
        functions=len(module.functions),
        blocks=sum(len(function.blocks) for function in module.functions),
        operations=sum(
            len(block.operations) for function in module.functions for block in function.blocks
        ),
        sliced_operations=statistics.sliced_operations,
        symbolic_branches=statistics.symbolic_branches,
        path_constraints=statistics.path_constraints,
        solver_calls=statistics.solver_calls,
        peak_states=statistics.peak_states,
    )


def table(records: list[Record]) -> str:
    header = (
        "| fixture | variant | status | ghidra s | lift s | simplify s | slice s | explore s "
        "| solver s | total s | blocks | ops | sliced | branches | constraints | solver calls "
        "| peak states |"
    )
    lines = [header, "|" + "---|" * 17]
    for item in records:
        lines.append(
            f"| {item.fixture} | {item.variant} | {item.status} | {item.ghidra_seconds:.2f} "
            f"| {item.lift_seconds:.2f} | {item.simplify_seconds:.2f} | {item.slice_seconds:.3f} "
            f"| {item.exploration_seconds:.2f} | {item.solver_seconds:.2f} "
            f"| {item.total_seconds:.2f} | {item.blocks} | {item.operations} "
            f"| {item.sliced_operations} | {item.symbolic_branches} | {item.path_constraints} "
            f"| {item.solver_calls} | {item.peak_states} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Time each stage of solving the fixtures.")
    parser.add_argument("--fixtures", help="comma-separated fixture names (default: all)")
    parser.add_argument(
        "--variants", default="gcc-O0,gcc-O2,clang-O0,clang-O2", help="compiler-level labels"
    )
    parser.add_argument("--timeout", type=float, default=120.0, help="solve budget per binary")
    parser.add_argument("--fresh", action="store_true", help="re-run Ghidra instead of the cache")
    parser.add_argument("--json", type=Path, help="also write the records here")
    arguments = parser.parse_args()
    selected: str | None = arguments.fixtures
    names = (
        selected.split(",")
        if selected
        else [name for name in fixture_names() if name not in SKIPPED]
    )
    variants: list[Variant] = []
    for label in str(arguments.variants).split(","):
        compiler, level = label.split("-")
        variants.append(Variant(compiler, level))
    analyzer = Analyzer(
        AnalyzerConfig(
            cache=CacheOptions(enabled=not arguments.fresh, directory=BUILD_ROOT / "cache")
        )
    )
    records: list[Record] = []
    for name in names:
        for variant in variants:
            try:
                record = measure(analyzer, name, variant, float(arguments.timeout))
            except PpyRevError as error:
                print(f"{name} {variant.label}: {error}", file=sys.stderr)
                continue
            records.append(record)
            print(
                f"{name} {variant.label}: {record.status} in {record.total_seconds:.1f}s",
                file=sys.stderr,
            )
    print(table(records))
    json_path: Path | None = arguments.json
    if json_path is not None:
        json_path.write_text(json.dumps([asdict(item) for item in records], indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

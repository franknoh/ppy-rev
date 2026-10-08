"""Rich-styled terminal output, used only when writing to a real terminal.

When stdout is piped or captured, `console_for` returns None and the plain renderers in
`render.py` run instead, so other tools and the tests read exactly the same text as before.
An interactive terminal gets the color, panels, and VM views built here.
"""

from __future__ import annotations

import json
import os
from typing import TextIO

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ppy_rev.analysis.goals import GoalCandidate
from ppy_rev.analysis.report import AnalysisReport
from ppy_rev.cli.render import solution_bytes
from ppy_rev.doctor import Diagnosis
from ppy_rev.info import ProgramInfo
from ppy_rev.solve import SolveResult, SolveStatus
from ppy_rev.vm.detect import Dispatcher
from ppy_rev.vm.lift import LiftedVm

BANNER = (
    "██████╗ ██████╗ ██╗   ██╗      ██████╗ ███████╗██╗   ██╗\n"
    "██╔══██╗██╔══██╗╚██╗ ██╔╝      ██╔══██╗██╔════╝██║   ██║\n"
    "██████╔╝██████╔╝ ╚████╔╝ █████╗██████╔╝█████╗  ██║   ██║\n"
    "██╔═══╝ ██╔═══╝   ╚██╔╝  ╚════╝██╔══██╗██╔══╝  ╚██╗ ██╔╝\n"
    "██║     ██║        ██║         ██║  ██║███████╗ ╚████╔╝ \n"
    "╚═╝     ╚═╝        ╚═╝         ╚═╝  ╚═╝╚══════╝  ╚═══╝  "
)
_BANNER_SHADES = ("red1", "red1", "red3", "red3", "dark_red", "dark_red")

_PRINTABLE = frozenset(range(0x20, 0x7F))
_ACCENT = "bright_red"
_MUTED = "grey62"
_STATUS = {
    SolveStatus.SAT: ("bold green", "●"),
    SolveStatus.UNSAT: ("bold red", "○"),
}
_CERTAINTY = {"proven": "green", "inferred": "yellow", "heuristic": _MUTED}


def console_for(out: TextIO) -> Console | None:
    """A console for a real terminal, or None when output is piped or captured."""
    if os.environ.get("NO_COLOR"):
        return None
    isatty = getattr(out, "isatty", None)
    if not callable(isatty) or not isatty():
        return None
    return Console(file=out, highlight=False, emoji=False)


def banner(console: Console, tagline: str = "lift · solve · defuse") -> None:
    console.print()
    for line, shade in zip(BANNER.splitlines(), _BANNER_SHADES, strict=False):
        console.print(Text(line, style=f"bold {shade}"))
    console.print(Text(f"  {tagline}", style=_ACCENT))
    console.print()


def _field_table(rows: list[tuple[str, RenderableType]]) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style=_MUTED, justify="right")
    table.add_column()
    for name, value in rows:
        table.add_row(name, value)
    return table


def _bytes_text(data: bytes) -> Text:
    trimmed = data.rstrip(b"\n")
    if not trimmed:
        return Text("(empty)", style=_MUTED)
    if all(byte in _PRINTABLE for byte in trimmed):
        return Text(trimmed.decode("ascii"), style="bold")
    escaped = "".join(
        chr(b) if b in _PRINTABLE and b != 0x5C else ("\\n" if b == 0x0A else f"\\x{b:02x}")
        for b in data
    )
    return Text.assemble((escaped, "bold"), ("\n" + data.hex(" "), _MUTED))


# -- solve -----------------------------------------------------------------------------------


def solve(result: SolveResult, console: Console, verbose: int) -> None:
    banner(console, "solve")
    goal = result.goal
    first = result.solutions[0] if result.solutions else None
    rows: list[tuple[str, RenderableType]] = [("target", Text(result.target))]
    for item in result.inputs:
        label = item.label()
        if first is not None:
            data = first.argv if item.index is not None else first.stdin
            if data is not None:
                label += f"   len {len(data.rstrip(b'\n'))}"
        rows.append(("input", Text(label)))
    call = Text()
    call.append(f"{goal.address:#x}", style=_ACCENT)
    if goal.text and goal.call:
        call.append(f"  {goal.call}({json.dumps(goal.text)})")
    elif goal.text:
        call.append(f"  uses {json.dumps(goal.text)}")
    rows.append(("goal", call))
    console.print(
        Panel(_field_table(rows), title="solve", title_align="left", box=box.ROUNDED, expand=False)
    )

    style, mark = _STATUS.get(result.status, ("bold yellow", "◌"))
    status = Text.assemble(("  result   ", _MUTED), (f"{mark} {result.status}", style))
    status.append(f"    {result.backend} · {result.statistics.seconds:.2f}s", style=_MUTED)
    console.print(status)
    for index, solution in enumerate(result.solutions):
        label = "answer" if len(result.solutions) == 1 else f"answer {index + 1}"
        console.print(
            Text.assemble((f"  {label:<8} ", _MUTED), _bytes_text(solution_bytes(solution)))
        )
        for name, content in solution.files:
            console.print(Text.assemble((f"    {name}: ", _MUTED), _bytes_text(content)))
        verified = solution.verified
        tick = Text.assemble(
            ("  verify   ", _MUTED),
            ("✓ " if verified else "✗ ", "green" if verified else "red"),
            (solution.verification, _MUTED),
        )
        console.print(tick)
        if solution.native is not None:
            passed = solution.native.passed
            word, colour = (
                ("inconclusive", "yellow")
                if passed is None
                else ("passed", "green")
                if passed
                else ("failed", "red")
            )
            console.print(
                Text.assemble(
                    ("  native   ", _MUTED), (word, colour), (f"  {solution.native.detail}", _MUTED)
                )
            )
    _solve_notes(result, console, verbose)
    if verbose:
        _solve_stats(result, console)


def _solve_notes(result: SolveResult, console: Console, verbose: int) -> None:
    always = ("the program mentions", "code runs before main", "the goal is reached without")
    if result.status is SolveStatus.SAT and not verbose:
        notes: list[str] = [note for note in result.notes if note.startswith(always)]
    else:
        notes = list(result.notes)
    if not notes:
        return
    console.print()
    for note in notes:
        console.print(Text.assemble(("  · ", _MUTED), note))


def _solve_stats(result: SolveResult, console: Console) -> None:
    statistics = result.statistics
    rows = [
        ("functions", str(statistics.functions_lifted)),
        ("blocks", str(statistics.relevant_blocks)),
        ("operations", str(statistics.symbolic_operations)),
        ("branches", str(statistics.symbolic_branches)),
        ("states", str(statistics.states)),
        ("solver calls", str(statistics.solver_calls)),
    ]
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style=_MUTED, justify="right")
    grid.add_column(justify="right")
    for name, value in rows:
        grid.add_row(name, value)
    console.print()
    console.print(Panel(grid, title="analysis", title_align="left", box=box.ROUNDED, expand=False))


# -- vm --------------------------------------------------------------------------------------


def dispatchers(target: str, items: list[Dispatcher], hidden: int, console: Console) -> None:
    banner(console, "vm detect")
    console.print(Text.assemble(("target  ", _MUTED), target))
    if not items:
        console.print(Text("\nNo VM dispatcher found.", style="yellow"))
        return
    for dispatcher in items:
        head = _field_table(
            [
                ("where", Text(f"{dispatcher.address:#x} in {dispatcher.function}")),
                ("confidence", Text(f"{dispatcher.confidence:.2f}")),
            ]
        )
        evidence = Table.grid(padding=(0, 1))
        evidence.add_column()
        evidence.add_column()
        for item in dispatcher.evidence:
            colour = _CERTAINTY.get(item.certainty, _MUTED)
            evidence.add_row(Text(f"[{item.certainty}]", style=colour), Text(item.text))
        handlers = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
        handlers.add_column("handler", style=_ACCENT)
        handlers.add_column("opcodes")
        handlers.add_column("")
        for handler in sorted(dispatcher.handlers, key=lambda h: (h.opcodes[:1], h.address)):
            leaves = "" if handler.returns_to_dispatcher else "leaves the loop"
            handlers.add_row(
                f"{handler.address:#x}", _opcodes(handler.opcodes), Text(leaves, style=_MUTED)
            )
        body = Group(
            head,
            Text("\nevidence", style=_MUTED),
            evidence,
            Text("\nhandlers", style=_MUTED),
            handlers,
        )
        console.print(Panel(body, title="dispatcher", title_align="left", box=box.ROUNDED))
    if hidden:
        console.print(
            Text(f"\n{hidden} unlikely candidates hidden (--all shows them)", style=_MUTED)
        )


def _opcodes(values: tuple[int, ...]) -> str:
    if not values:
        return "opcodes not evaluated"
    shown = " ".join(f"{value:#04x}" for value in values[:6])
    return shown + (f" +{len(values) - 6}" if len(values) > 6 else "")


def lifted_vm(target: str, lifted: LiftedVm, console: Console) -> None:
    banner(console, "vm lift")
    dispatcher = lifted.dispatcher
    counters = {item.counter for item in lifted.instructions}
    rows: list[tuple[str, RenderableType]] = [
        ("target", Text(target)),
        ("dispatcher", Text(f"{dispatcher.address:#x} in {dispatcher.function}")),
        ("lifted", Text(f"{len(counters)} instructions · {len(lifted.opcodes)} opcodes")),
    ]
    if lifted.bytecode_base is not None:
        rows.insert(2, ("bytecode", Text(f"{lifted.bytecode_base:#x}")))
    console.print(
        Panel(
            _field_table(rows), title="vm lift", title_align="left", box=box.ROUNDED, expand=False
        )
    )

    opcodes = Table(
        title="instruction set", box=box.SIMPLE, title_style=_MUTED, title_justify="left"
    )
    opcodes.add_column("op", style=_ACCENT)
    opcodes.add_column("n", justify="right", style=_MUTED)
    opcodes.add_column("bytes", justify="right")
    opcodes.add_column("flow")
    for opcode in lifted.opcodes:
        flow = Text()
        if opcode.branches:
            flow.append("branches ", style="yellow")
        if opcode.exits:
            flow.append("exits " + ", ".join(opcode.exits), style="red")
        opcodes.add_row(
            opcode.name,
            str(opcode.instances),
            "/".join(str(length) for length in opcode.lengths),
            flow,
        )
    console.print(opcodes)

    tree = Tree(Text("bytecode", style=_MUTED))
    for item in lifted.instructions:
        line = Text.assemble(
            (f"{item.counter:#06x}  ", _MUTED), (f"{item.name:<6} ", _ACCENT), item.bytes.hex(" ")
        )
        if item.successors:
            line.append("  → " + ", ".join(f"{s:#06x}" for s in item.successors), style=_MUTED)
        if item.exits:
            line.append("  " + "; ".join(item.exits), style="red")
        node = tree.add(line)
        for effect in item.effects:
            node.add(Text(effect, style=_MUTED))
    console.print(tree)


# -- analyze ---------------------------------------------------------------------------------


def analysis(report: AnalysisReport, console: Console, verbose: int) -> None:
    banner(console, "analyze")
    console.print(
        _field_table(
            [("target", Text(report.target)), ("entry", Text(report.main or "main not found"))]
        )
    )
    inputs = ", ".join(
        f"argv[{item.index}]" if item.index is not None else item.name or "stdin"
        for item in report.inputs
    )
    console.print(Text.assemble(("\ninputs    ", _MUTED), inputs or "none discovered"))
    _outcome_table(console, "success", report.successes or (), "green")
    _outcome_table(console, "failure", report.failures, "red")
    if report.flag_formats:
        shapes = ", ".join(f"{prefix}*}}" for prefix in report.flag_formats)
        console.print(Text.assemble(("\nflag format  ", _MUTED), (shapes, _ACCENT)))
    reachable = [item for item in report.functions if item.reachable]
    console.print(
        Text.assemble(
            ("\nreachable from main  ", _MUTED), f"{len(reachable)} of {len(report.functions)}"
        )
    )
    for dispatcher in report.dispatchers:
        where = (
            f"{dispatcher.address:#x} in {dispatcher.function} "
            f"({len(dispatcher.handlers)} handlers)"
        )
        console.print(Text.assemble(("vm  ", _MUTED), where))


def _outcome_table(
    console: Console, kind: str, candidates: tuple[GoalCandidate, ...], colour: str
) -> None:
    console.print(Text(f"\n{kind} candidates", style=_MUTED))
    if not candidates:
        console.print(Text("  none", style=_MUTED))
        return
    table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
    table.add_column("", justify="right", style=_MUTED)
    table.add_column("", style=colour)
    table.add_column("")
    for candidate in candidates:
        if candidate.text:
            use = (
                f"{candidate.call}({json.dumps(candidate.text)})"
                if candidate.call
                else candidate.text
            )
        else:
            use = f"calls {candidate.call}" if candidate.call else "runs"
        table.add_row(
            f"{candidate.confidence:.2f}",
            f"{candidate.address:#x}",
            f"{use}  ·  {candidate.function}",
        )
    console.print(table)


# -- info ------------------------------------------------------------------------------------


def info(program: ProgramInfo, console: Console) -> None:
    banner(console, "info")
    kind = f"{program.format} {program.elf_type}"
    target = f"{program.architecture} {program.endianness}-endian {kind}"
    rows: list[tuple[str, RenderableType]] = [
        ("target", Text(target)),
        (
            "entry",
            Text(
                f"{program.entry:#x}"
                + (f" ({program.entry_symbol})" if program.entry_symbol else "")
            ),
        ),
        ("ghidra", Text(f"{program.ghidra_language} ({program.compiler})")),
    ]
    if program.sha256:
        rows.append(("sha-256", Text(program.sha256, style=_MUTED)))
    console.print(
        Panel(_field_table(rows), title="info", title_align="left", box=box.ROUNDED, expand=False)
    )
    sections = Table(title="sections", box=box.SIMPLE, title_style=_MUTED, title_justify="left")
    sections.add_column("name", style=_ACCENT)
    sections.add_column("start")
    sections.add_column("size", justify="right")
    sections.add_column("perm")
    for section in program.sections:
        sections.add_row(
            section.name, f"{section.start:#010x}", str(section.size), section.permissions
        )
    console.print(sections)
    console.print(Text(f"functions  {len(program.functions)}", style=_MUTED))
    if program.imports:
        console.print(Text.assemble(("imports  ", _MUTED), ", ".join(program.imports)))


# -- doctor ----------------------------------------------------------------------------------


def doctor(diagnosis: Diagnosis, console: Console) -> None:
    banner(console, "doctor")
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="center")
    table.add_column(style=_MUTED)
    table.add_column()
    for check in diagnosis.checks:
        mark = Text("✓", style="green") if check.ok else Text("✗", style="red")
        table.add_row(mark, check.name, Text(check.detail, style="" if check.ok else "red"))
        if check.hint:
            lead = "note: " if check.ok else "→ "
            table.add_row("", "", Text(lead + check.hint, style=_MUTED))
    console.print(table)
    console.print()

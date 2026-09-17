"""Human-readable rendering of analysis results."""

from __future__ import annotations

import json
from typing import TextIO

from ppy_rev.info import ProgramInfo
from ppy_rev.solve import Solution, SolveResult, SolveStatus
from ppy_rev.vm.detect import Dispatcher
from ppy_rev.vm.lift import LiftedVm

_PRINTABLE = frozenset(range(0x20, 0x7F))


def render_info(info: ProgramInfo, out: TextIO) -> None:
    kind = f"{info.format} {info.elf_type}"
    out.write(f"Target: {info.architecture} {info.endianness}-endian {kind}\n")
    if info.sha256:
        out.write(f"SHA-256: {info.sha256}\n")
    entry_name = f" ({info.entry_symbol})" if info.entry_symbol else ""
    out.write(f"Entry: {info.entry:#x}{entry_name}\n")
    out.write(f"Ghidra language: {info.ghidra_language} ({info.compiler})\n")
    out.write(f"Image base: {info.image_base:#x}\n")
    out.write("\nSections:\n")
    width = max((len(section.name) for section in info.sections), default=0)
    for section in info.sections:
        out.write(
            f"  {section.name:<{width}}  {section.start:#010x}  "
            f"{section.size:>8}  {section.permissions}\n"
        )
    out.write(f"\nFunctions ({len(info.functions)}):\n")
    for function in info.functions:
        thunk = f"  -> {function.thunk_of}" if function.thunk_of else ""
        out.write(f"  {function.entry:#010x}  {function.name}{thunk}\n")
    if info.imports:
        out.write(f"\nImports: {', '.join(info.imports)}\n")


def solution_bytes(solution: Solution) -> bytes:
    return solution.argv if solution.argv is not None else solution.stdin or b""


def _escaped(data: bytes) -> str:
    parts: list[str] = []
    for byte in data:
        if byte in _PRINTABLE and byte != 0x5C:
            parts.append(chr(byte))
        elif byte == 0x0A:
            parts.append("\\n")
        else:
            parts.append(f"\\x{byte:02x}")
    return "".join(parts)


def render_solve(result: SolveResult, out: TextIO, verbose: int) -> None:
    out.write(f"Target: {result.target}\n\nInput:\n")
    first = result.solutions[0] if result.solutions else None
    for item in result.inputs:
        out.write(f"  {item.label()}\n")
        if first is not None:
            data = first.argv if item.index is not None else first.stdin
            if data is not None:
                out.write(f"  inferred length: {len(data.rstrip(b'\n'))}\n")
        if verbose:
            for evidence in item.evidence:
                out.write(f"    evidence: {evidence}\n")
    goal = result.goal
    out.write(f"\nGoal:\n  reaches {goal.address:#x}\n")
    if goal.text and goal.call:
        out.write(f"  calls {goal.call}({json.dumps(goal.text)})\n")
    elif goal.text:
        out.write(f"  uses {json.dumps(goal.text)}\n")
    if verbose:
        out.write(f"  confidence: {goal.confidence:.2f}\n")
        for evidence in goal.evidence:
            out.write(f"    evidence: {evidence}\n")
        for candidate in result.avoid:
            label = f" {candidate.text!r}" if candidate.text else ""
            out.write(f"  avoids {candidate.address:#x}{label}\n")
    statistics = result.statistics
    out.write(
        "\nAnalysis:\n"
        f"  functions lifted: {statistics.functions_lifted}\n"
        f"  relevant blocks: {statistics.relevant_blocks}\n"
        f"  symbolic operations: {statistics.symbolic_operations}\n"
        f"  symbolic branches: {statistics.symbolic_branches}\n"
    )
    if verbose:
        out.write(
            f"  states: {statistics.states}\n"
            f"  solver calls: {statistics.solver_calls}\n"
            f"  sliced operations: {statistics.sliced_operations}\n"
            f"  seconds: {statistics.seconds:.2f}\n"
        )
    out.write(f"\nSolver:\n  backend: {result.backend}\n  result: {result.status}\n")
    if result.status is not SolveStatus.SAT or verbose:
        for note in result.notes:
            out.write(f"  note: {note}\n")
    for index, solution in enumerate(result.solutions):
        heading = "Solution" if len(result.solutions) == 1 else f"Solution {index + 1}"
        data = solution_bytes(solution)
        out.write(f"\n{heading}:\n")
        if all(byte in _PRINTABLE for byte in data.rstrip(b"\n")):
            out.write(f"  {data.rstrip(b'\n').decode('ascii')}\n")
        else:
            out.write(f"  ASCII: {_escaped(data)}\n  Hex:   {data.hex(' ')}\n")
        verdict = "passed" if solution.verified else "failed"
        out.write(f"\nVerification:\n  RevIR execution: {verdict} ({solution.verification})\n")
        if solution.native is not None:
            passed = solution.native.passed
            native = "inconclusive" if passed is None else "passed" if passed else "failed"
            out.write(f"  native (sandboxed): {native} ({solution.native.detail})\n")
    if verbose > 1 and result.constraints:
        out.write("\nConstraints:\n")
        for constraint in result.constraints:
            where = f"{constraint.function or '?'}"
            address = f" {constraint.address:#x}" if constraint.address is not None else ""
            out.write(f"  [{constraint.kind}] {constraint.text}\n    from {where}{address}\n")


_OPCODES_SHOWN = 6


def _opcodes(values: tuple[int, ...]) -> str:
    if not values:
        return "opcodes not evaluated"
    shown = " ".join(f"{value:#04x}" for value in values[:_OPCODES_SHOWN])
    label = "opcode" if len(values) == 1 else "opcodes"
    more = len(values) - _OPCODES_SHOWN
    return f"{label} {shown}" + (f" and {more} more" if more > 0 else "")


def render_dispatchers(
    target: str, dispatchers: list[Dispatcher], hidden: int, out: TextIO
) -> None:
    out.write(f"Target: {target}\n")
    if not dispatchers:
        out.write("\nNo VM dispatcher found.\n")
    for dispatcher in dispatchers:
        out.write(
            f"\nCandidate dispatcher: {dispatcher.address:#x} in {dispatcher.function}\n"
            f"  confidence: {dispatcher.confidence:.2f}\n"
        )
        if dispatcher.loop_header is not None:
            out.write(f"  dispatch loop: {dispatcher.loop_header:#x}\n")
        fetch = dispatcher.fetch
        if fetch is not None:
            sites = ", ".join(f"{address:#x}" for address in fetch.instructions)
            out.write(f"  opcode fetch: {fetch.width}-bit load of {fetch.address} at {sites}\n")
            if fetch.program_counter is not None:
                out.write(f"  VM program counter: {fetch.program_counter}\n")
            if fetch.bytecode_base is not None:
                region = f" ({fetch.bytecode_region})" if fetch.bytecode_region else ""
                out.write(f"  bytecode: {fetch.bytecode_base:#x}{region}\n")
        out.write("\n  evidence:\n")
        for item in dispatcher.evidence:
            out.write(f"    [{item.certainty}] {item.text}\n")
        out.write(f"\n  handlers ({len(dispatcher.handlers)}):\n")
        for handler in sorted(
            dispatcher.handlers, key=lambda item: (item.opcodes[:1], item.address)
        ):
            loop = "" if handler.returns_to_dispatcher else "  (leaves the loop)"
            out.write(f"    {handler.address:#x}  {_opcodes(handler.opcodes)}{loop}\n")
    if hidden:
        out.write(f"\n{hidden} unlikely candidates hidden (--all shows them)\n")


def render_lifted_vm(target: str, lifted: LiftedVm, out: TextIO) -> None:
    dispatcher = lifted.dispatcher
    out.write(
        f"Target: {target}\n\n"
        f"Dispatcher: {dispatcher.address:#x} in {dispatcher.function} "
        f"(confidence {dispatcher.confidence:.2f})\n"
    )
    if lifted.bytecode_base is not None:
        out.write(f"Bytecode: {lifted.bytecode_base:#x}\n")
    counters = {item.counter for item in lifted.instructions}
    out.write(
        f"Lifted: {len(counters)} instructions, {len(lifted.opcodes)} opcodes, "
        f"{len(lifted.function.blocks)} RevIR blocks\n"
    )
    if lifted.guards:
        out.write("Specialized for:\n")
        for guard in lifted.guards:
            out.write(f"  {guard.describe()}\n")
    out.write("\nInstruction set (names are neutral; effects are observed, not guessed):\n")
    for opcode in lifted.opcodes:
        lengths = "/".join(str(length) for length in opcode.lengths)
        flags = " branches" if opcode.branches else ""
        exits = f" exits: {', '.join(opcode.exits)}" if opcode.exits else ""
        handler = f" handler {opcode.handler:#x}" if opcode.handler is not None else ""
        out.write(
            f"  {opcode.name}  {opcode.instances} instance(s), {lengths} bytes{handler}"
            f"{flags}{exits}\n"
        )
    out.write("\nBytecode:\n")
    for item in lifted.instructions:
        successors = ", ".join(f"{successor:#06x}" for successor in item.successors)
        exits = "; ".join(item.exits)
        flow = " ".join(part for part in (f"-> {successors}" if successors else "", exits) if part)
        out.write(f"  {item.counter:#06x}  {item.name:<6} {item.bytes.hex(' '):<14} {flow}\n")
        for effect in item.effects:
            out.write(f"          {effect}\n")

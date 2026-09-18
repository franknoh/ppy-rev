"""What a program prints, for when no message ranks as a success outcome."""

from __future__ import annotations

from ppy_rev.analysis.program import StringReference, string_references
from ppy_rev.analysis.slicing import OUTPUT_FUNCTIONS
from ppy_rev.ir.model import Function, Module

LISTED = 12
"""How many messages to show before saying how many more there are."""


def printed_messages(module: Module, reachable: list[Function]) -> tuple[tuple[int, str], ...]:
    """Each message the reachable code prints, with the instruction that prints it."""
    return printed_messages_from(string_references(module, reachable))


def printed_messages_from(
    references: list[StringReference],
) -> tuple[tuple[int, str], ...]:
    seen: dict[bytes, int] = {}
    for reference in references:
        if reference.call in OUTPUT_FUNCTIONS and reference.text not in seen:
            seen[reference.text] = reference.instruction
    return tuple(
        (address, text.decode("latin-1"))
        for text, address in sorted(seen.items(), key=lambda item: item[1])
    )


def describe_messages(messages: tuple[tuple[int, str], ...], limit: int = LISTED) -> str:
    """The same list as a block of text, for an error message."""
    if not messages:
        return ""
    lines = [f"  {address:#x}  {text!r}" for address, text in messages[:limit]]
    more = "" if len(messages) <= limit else f"\n  ... and {len(messages) - limit} more"
    return "\nthe program prints:\n" + "\n".join(lines) + more

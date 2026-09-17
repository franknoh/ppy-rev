"""Diagnostics and the error hierarchy for expected analysis failures.

Expected failures (missing Ghidra, unsupported semantics, malformed exports) raise
`PpyRevError` subclasses. The CLI reports those without a traceback; anything else is
an internal error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


class DiagnosticCode(StrEnum):
    UNSUPPORTED_OPERATION = "unsupported-operation"
    UNSUPPORTED_USER_OP = "unsupported-user-op"
    UNSUPPORTED_ADDRESS_SPACE = "unsupported-address-space"
    UNSUPPORTED_FLOAT_OPERATION = "unsupported-float-operation"
    SYMBOLIC_POINTER_REQUIRED = "symbolic-pointer-required"
    MISSING_INSTRUCTION = "missing-instruction"
    UNRESOLVED_INDIRECT_BRANCH = "unresolved-indirect-branch"
    MALFORMED_PCODE = "malformed-pcode"


@dataclass(frozen=True, slots=True)
class Location:
    """Where a diagnostic applies. Every field is optional; fill in what is known."""

    function: str | None = None
    block: int | None = None
    address: int | None = None
    opcode: str | None = None
    widths: tuple[int, ...] = ()

    def describe(self) -> str:
        parts: list[str] = []
        if self.function is not None:
            parts.append(f"function {self.function}")
        if self.block is not None:
            parts.append(f"block {self.block}")
        if self.address is not None:
            parts.append(f"at {self.address:#x}")
        if self.opcode is not None:
            parts.append(f"op {self.opcode}")
        if self.widths:
            parts.append("widths " + "/".join(str(width) for width in self.widths))
        return ", ".join(parts)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: DiagnosticCode
    message: str
    location: Location = field(default_factory=Location)
    severity: Severity = Severity.ERROR

    def render(self) -> str:
        where = self.location.describe()
        suffix = f" ({where})" if where else ""
        return f"{self.severity}[{self.code}]: {self.message}{suffix}"


class PpyRevError(Exception):
    """An expected failure that should be reported to the user without a traceback."""


class ConfigurationError(PpyRevError):
    pass


class UnsupportedBinaryError(PpyRevError):
    pass


class GhidraError(PpyRevError):
    pass


class ExportFormatError(PpyRevError):
    pass

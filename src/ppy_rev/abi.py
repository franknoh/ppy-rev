"""Calling-convention facts about code outside the lifted module.

Lifted functions describe their own register interfaces exactly. These sets are the
assumptions made about everything else: imported functions (what they may read and
clobber) and callers outside the module (what they may observe after a return).
"""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.diagnostics import UnsupportedBinaryError
from ppy_rev.ir.model import Target

_VECTOR = tuple(f"ZMM{index}" for index in range(32))
_ARITHMETIC_FLAGS = ("CF", "PF", "AF", "ZF", "SF", "OF")


@dataclass(frozen=True, slots=True)
class CallingConvention:
    name: str
    integer_parameters: tuple[str, ...]
    integer_returns: tuple[str, ...]
    reads: frozenset[str]
    """Registers a conforming callee may read on entry."""
    clobbers: frozenset[str]
    """Registers a conforming callee may leave changed."""
    observed: frozenset[str]
    """Registers a conforming caller may read after the callee returns."""


SYSV_X86_64 = CallingConvention(
    name="System V AMD64",
    integer_parameters=("RDI", "RSI", "RDX", "RCX", "R8", "R9"),
    integer_returns=("RAX", "RDX"),
    reads=frozenset(
        {"RDI", "RSI", "RDX", "RCX", "R8", "R9", "RAX", "RSP", "FS_OFFSET", *_VECTOR[:8]}
    ),
    clobbers=frozenset(
        {"RAX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "RSP"}
        | set(_ARITHMETIC_FLAGS)
        | set(_VECTOR)
    ),
    observed=frozenset(
        {"RAX", "RDX", "RSP", "RBX", "RBP", "R12", "R13", "R14", "R15", "DF"}
        | {"FS_OFFSET", "GS_OFFSET", "ZMM0", "ZMM1"}
    ),
)


def calling_convention(target: Target) -> CallingConvention:
    if target.architecture == "x86-64":
        return SYSV_X86_64
    raise UnsupportedBinaryError(f"no calling convention model for {target.architecture}")

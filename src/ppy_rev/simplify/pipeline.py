"""The deterministic simplification pipeline applied before emission and solving."""

from __future__ import annotations

from dataclasses import replace

from ppy_rev.ir.model import Function, Module
from ppy_rev.ir.transform import renumber
from ppy_rev.simplify.cfg import simplify_cfg
from ppy_rev.simplify.cse import eliminate_common_subexpressions
from ppy_rev.simplify.dce import eliminate_dead_code
from ppy_rev.simplify.fold import fold_function
from ppy_rev.simplify.interfaces import trim_interfaces
from ppy_rev.simplify.memory import forward_memory

_ROUNDS = 20


def simplify_module(module: Module) -> Module:
    """Narrow register interfaces, then simplify each function to a fixpoint."""
    trimmed = trim_interfaces(module)
    return replace(
        trimmed,
        functions=tuple(simplify_function(trimmed, function) for function in trimmed.functions),
    )


def simplify_function(module: Module, function: Function) -> Function:
    target = module.target
    for _ in range(_ROUNDS):
        folded = fold_function(function)
        forwarded = forward_memory(folded, target.endianness, target.pointer_width)
        simplified = simplify_cfg(eliminate_dead_code(eliminate_common_subexpressions(forwarded)))
        if simplified == function:
            break
        function = simplified
    return renumber(function)

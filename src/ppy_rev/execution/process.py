"""Process layout for executing lifted code outside the original process.

Addresses are fixed so that executions (and the models derived from them) are
deterministic. The layout mirrors a Linux x86-64 user process closely enough for
position-independent user code: a downward-growing stack, and a thread control block
whose stack-protector canary lives at fs:0x28.
"""

from __future__ import annotations

from dataclasses import dataclass

from ppy_rev.execution.memory import ConcreteMemory, Mapping
from ppy_rev.ir.model import Module

STACK_TOP = 0x7FFF_FFFF_0000
STACK_SIZE = 0x10_0000
STACK_START = STACK_TOP - STACK_SIZE
INITIAL_STACK_POINTER = STACK_TOP - 0x2000
THREAD_BLOCK = 0x7FFF_F7D0_0000
THREAD_BLOCK_SIZE = 0x1000
STACK_CANARY = 0x2F8E_61A5_C0DE_1100
RETURN_SENTINEL = 0x0000_7FFF_DEAD_0000
"""Return address pushed for the outermost call; returning there ends the execution."""


@dataclass(frozen=True, slots=True)
class CallFrame:
    registers: dict[str, int]
    return_address: int


def standard_memory(module: Module) -> ConcreteMemory:
    """Module image plus a stack and a thread control block."""
    memory = ConcreteMemory.for_module(module)
    memory.map(Mapping("[stack]", STACK_START, STACK_SIZE, True, True, None))
    memory.map(Mapping("[tls]", THREAD_BLOCK, THREAD_BLOCK_SIZE, True, True, None))
    memory.store(THREAD_BLOCK, THREAD_BLOCK, module.target.pointer_width)
    memory.store(THREAD_BLOCK + 0x28, STACK_CANARY, module.target.pointer_width)
    return memory


def enter_call(module: Module, memory: ConcreteMemory, registers: dict[str, int]) -> CallFrame:
    """Set up registers as a `call` instruction would leave them on entry to a function."""
    pointer_width = module.target.pointer_width
    stack_pointer = INITIAL_STACK_POINTER - pointer_width // 8
    memory.store(stack_pointer, RETURN_SENTINEL, pointer_width)
    state = dict(registers)
    state[module.target.stack_pointer] = stack_pointer
    names = {register.name for register in module.registers}
    if "FS_OFFSET" in names:
        state.setdefault("FS_OFFSET", THREAD_BLOCK)
    return CallFrame(state, RETURN_SENTINEL)

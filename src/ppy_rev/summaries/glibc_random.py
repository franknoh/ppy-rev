"""glibc's rand and srand: the additive feedback generator behind random_r (TYPE_3).

The generator is fully determined by its seed, and a program that never calls srand
behaves as if it called srand(1).
"""

from __future__ import annotations

from dataclasses import dataclass

DEGREE = 31
SEPARATION = 3
_MODULUS = 2147483647


@dataclass(frozen=True, slots=True)
class RandomState:
    table: tuple[int, ...]
    """The 31 state words, as unsigned 32-bit values."""
    front: int
    rear: int


def _int32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value >> 31 else value


def _c_divmod(dividend: int, divisor: int) -> tuple[int, int]:
    """C division: the quotient truncates toward zero, the remainder takes the dividend's sign."""
    quotient = abs(dividend) // abs(divisor)
    if (dividend < 0) != (divisor < 0):
        quotient = -quotient
    return quotient, dividend - quotient * divisor


def seeded(seed: int) -> RandomState:
    """The state after srand(seed)."""
    seed &= 0xFFFFFFFF
    if seed == 0:
        seed = 1
    word = _int32(seed)
    table = [seed]
    for _ in range(1, DEGREE):
        # state[i] = (16807 * state[i - 1]) % 2147483647, computed without overflowing 31 bits
        high, low = _c_divmod(word, 127773)
        word = _int32(16807 * low - 2836 * high)
        if word < 0:
            word += _MODULUS
        table.append(word & 0xFFFFFFFF)
    state = RandomState(tuple(table), SEPARATION, 0)
    for _ in range(10 * DEGREE):
        state, _ = advance(state)
    return state


def advance(state: RandomState) -> tuple[RandomState, int]:
    """The next rand() result and the state after it."""
    table = list(state.table)
    value = (table[state.front] + table[state.rear]) & 0xFFFFFFFF
    table[state.front] = value
    front, rear = state.front + 1, state.rear + 1
    if front >= DEGREE:
        front = 0
    elif rear >= DEGREE:
        rear = 0
    return RandomState(tuple(table), front, rear), value >> 1


UNSEEDED = seeded(1)
"""The state of a program that never called srand."""

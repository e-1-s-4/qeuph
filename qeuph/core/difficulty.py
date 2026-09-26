"""
Difficulty retargeting (whitepaper section 4.1: every 2048 blocks).

new_target = parent_target * actual_timespan / expected_timespan

clamped to a factor of 4 in either direction, BTC-style, with all
arithmetic in integers (multiply before divide).

Ported from QRL's DifficultyTracker concept (qrl/core/DifficultyTracker.py)
to a bounded 2048-block interval scheme.
"""
from __future__ import annotations

from qeuph.core import pow as pow_mod


def retarget(prev_bits: int, actual_seconds: int, expected_seconds: int) -> int:
    if actual_seconds < 0:
        actual_seconds = 0
    target = pow_mod.bits_to_target(prev_bits)
    if target == 0:
        raise ValueError("zero target")
    new_target = target * actual_seconds // expected_seconds
    # clamp to [target/4, target*4]
    lo = target // 4
    hi = target * 4
    if new_target < lo:
        new_target = lo
    elif new_target > hi:
        new_target = hi
    return pow_mod.target_to_bits(new_target)


def next_bits(parent_bits: int, parent_height: int, block_times: list,
              retarget_interval: int, block_time: int) -> int:
    """Compute bits for block at `parent_height + 1`.

    `block_times`: timestamps of the last `retarget_interval` blocks ending
    at parent_height (oldest first, i.e. [h - interval + 1 .. h]).  When
    fewer are available the first timestamp in the window is used.
    """
    height = parent_height
    if (height + 1) % retarget_interval != 0:
        return parent_bits
    window = retarget_interval
    if len(block_times) < 2:
        return parent_bits
    times = block_times[-window:]
    actual = times[-1] - times[0]
    expected = (len(times) - 1) * block_time
    if expected <= 0:
        return parent_bits
    return retarget(parent_bits, actual, expected)

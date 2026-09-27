"""
Block reward schedule: "two-thirding" (whitepaper section 4.3).

    reward(epoch) = floor( 50 QUH * (2/3)^epoch )      [quphi]

epoch = height // 210,000.  At 5 minute blocks one epoch is ~2 years;
the last non-zero epoch is 53 (reward 1 quphi) and the schedule ends
~108 years after genesis.  The sum over all epochs converges to at most
31,500,000 QUH (the geometric series 3 * 50 QUH * 210,000 blocks); the
iterated floor rounding leaves the exact emission at 31,499,999.8593 QUH,
i.e. 0.1407 QUH below the cap - Qeuph's analogue of Bitcoin never quite
reaching its 21M cap.
"""
from __future__ import annotations

from typing import Optional

from qeuph import constants as C


def epoch_at(height: int) -> int:
    return height // C.REWARD_INTERVAL


def epoch_rewards(limit: Optional[int] = None):
    """Reward of every epoch, iterating the exact integer floor each time.

    The floor is applied per epoch (exactly as Bitcoin floors its halvings),
    so the series cannot be shortcut with a single exponentiation: doing so
    would round differently and change the total emission.
    """
    rewards = []
    reward = C.REWARD_INITIAL
    n = 0
    while reward > 0 and (limit is None or n < limit):
        rewards.append(reward)
        reward = (reward * C.REWARD_NUMERATOR) // C.REWARD_DENOMINATOR
        n += 1
    return rewards


def epoch_count() -> int:
    """Number of epochs that pay a non-zero reward (54: epochs 0..53)."""
    return len(epoch_rewards())


def last_reward_height() -> int:
    """Start height of the final non-zero-reward epoch (11,130,000).

    Epoch 53 pays one quphi from here to height 11,339,999; epoch 54
    (11,340,000) pays nothing and miners earn fees only.
    """
    return (epoch_count() - 1) * C.REWARD_INTERVAL


def block_reward(height: int) -> int:
    """Reward in quphi (atomic units) at `height`, floored like Bitcoin."""
    if height < 0:
        raise ValueError("height must be non-negative")
    e = epoch_at(height)
    rewards = epoch_rewards(e + 1)
    if e >= len(rewards):
        return 0
    return rewards[e]


def total_supply_cap() -> int:
    return C.MAX_SUPPLY


def cumulative_emission(height: int) -> int:
    """Total quphi issued in every block up to and including `height`."""
    if height < 0:
        return 0
    rewards = epoch_rewards()
    total = 0
    for e, r in enumerate(rewards):
        start = e * C.REWARD_INTERVAL
        if start > height:
            break
        blocks = min(C.REWARD_INTERVAL, height - start + 1)
        total += r * blocks
    return total


def exact_total_emission() -> int:
    """Exact total quphi ever issued once every epoch has been mined.

    Equals 3,149,999,985,930,000 quphi = 31,499,999.8593 QUH, which is
    14,070,000 quphi (0.1407 QUH) below the 31,500,000 QUH cap.
    """
    return sum(r * C.REWARD_INTERVAL for r in epoch_rewards())


def emission_table(epochs: int = 60) -> list:
    """[(epoch, start_height, reward_quphi, reward_quh, cum_quphi)] for docs/tests."""
    rows = []
    cum = 0
    for e, r in enumerate(epoch_rewards(epochs)):
        cum += r * C.REWARD_INTERVAL
        rows.append((e, e * C.REWARD_INTERVAL, r, r / C.QUPHI_PER_QUH, cum))
    return rows

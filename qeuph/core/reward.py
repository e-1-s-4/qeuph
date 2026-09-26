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

from qeuph import constants as C


def epoch_at(height: int) -> int:
    return height // C.REWARD_INTERVAL


def block_reward(height: int) -> int:
    """Reward in quphi (atomic units) at `height`, floored like Bitcoin."""
    e = epoch_at(height)
    reward = C.REWARD_INITIAL
    for _ in range(e):
        reward = (reward * C.REWARD_NUMERATOR) // C.REWARD_DENOMINATOR
        if reward == 0:
            return 0
    return reward


def total_supply_cap() -> int:
    return C.MAX_SUPPLY


def emission_table(epochs: int = 60) -> list:
    """[(epoch, start_height, reward_quphi, reward_quh, cum_quphi)] for docs/tests."""
    rows = []
    cum = 0
    e = 0
    while e < epochs:
        r = block_reward(e * C.REWARD_INTERVAL)
        if r == 0 and e > 0:
            break
        cum += r * C.REWARD_INTERVAL
        rows.append((e, e * C.REWARD_INTERVAL, r, r / C.QUPHI_PER_QUH, cum))
        e += 1
    return rows


def exact_total_emission() -> int:
    """Exact total quphi ever issued once all epochs are mined (floored)."""
    return sum(block_reward(h) for h in range(0, 57 * C.REWARD_INTERVAL)) if False else \
        sum(r * C.REWARD_INTERVAL for r in [block_reward(e * C.REWARD_INTERVAL) for e in range(56)])

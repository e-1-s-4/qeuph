"""Merkle tree over transaction ids (double SHA3-512, pairwise)."""
from __future__ import annotations

from typing import List

from qeuph.crypto.address import dhash


def merkle_root(txids: List[bytes]) -> bytes:
    """BTC-style merkle root: pair from left, duplicate last on odd count."""
    if not txids:
        return bytes(64)
    level = list(txids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [dhash(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]

"""
Solo miner service.

Runs a dedicated thread that:
  1. asks the ChainManager for a block template (coinbase + best mempool txs)
  2. grinds the 16-byte header nonce with double SHA3-512
  3. submits the won block to the node for validation + relay

Ported from QRL's core/Miner.py + MiningAPIService split into one compact
service.  `hashrate()` reports measured hashes per second.
"""
from __future__ import annotations

import asyncio
import threading
import time
from typing import Optional

from qeuph import constants as C
from qeuph.core import pow as pow_mod


class SoloMiner:
    def __init__(self, node):
        self.node = node
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._payout: Optional[bytes] = None   # addr hash
        self._hash_count = 0
        self._hash_start = None
        self.blocks_mined = 0

    # ------------------------------------------------------------------
    def set_payout(self, addr_hash: bytes):
        self._payout = addr_hash

    @property
    def payout_address_hex(self) -> Optional[str]:
        if self._payout is None:
            return None
        from qeuph.crypto.address import hash_to_address
        return hash_to_address(self._payout, self.node.network.hrp)

    def start(self):
        if self._running.is_set():
            return
        if self._payout is None:
            raise ValueError("payout address not set")
        self._running.set()
        self._hash_start = time.time()
        self._thread = threading.Thread(target=self._mine_loop,
                                        daemon=True, name="qeuph-miner")
        self._thread.start()

    def stop(self):
        self._running.clear()

    def is_mining(self) -> bool:
        return self._running.is_set()

    def hashrate(self) -> float:
        if self._hash_start is None:
            return 0.0
        dt = time.time() - self._hash_start
        return self._hash_count / dt if dt > 0 else 0.0

    # ------------------------------------------------------------------
    def _mine_loop(self):
        loop = self.node_loop
        while self._running.is_set():
            try:
                self._mine_one(loop)
            except Exception as e:   # keep the miner alive
                time.sleep(0.5)
                _ = e

    @property
    def node_loop(self) -> asyncio.AbstractEventLoop:
        return self._loop

    _loop: Optional[asyncio.AbstractEventLoop] = None

    def attach_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    # ------------------------------------------------------------------
    def _mine_one(self, loop):
        chain = self.node.chain
        mempool = self.node.mempool
        # template
        try:
            txs = mempool.best_transactions(C.MAX_BLOCK_SIZE - 200_000)
        except Exception:
            txs = []
        block, reward = chain.create_block_template(self._payout, txs)
        # grind
        target = pow_mod.bits_to_target(block.header.bits)
        base = block.header.serialize()
        prefix = base[:-16]
        t0 = time.time()
        attempts = 0
        max_attempts = 1 << 28
        found = None
        while attempts < max_attempts and self._running.is_set():
            nonce = attempts
            blob = prefix + nonce.to_bytes(16, "little")
            self._hash_count += 1
            if int.from_bytes(pow_mod.dhash(blob), "big") < target:
                found = nonce
                break
            attempts += 1
        if found is None:
            return
        block.header.nonce = found
        # submit (validate + connect + relay) via the node event loop
        submit = asyncio.run_coroutine_threadsafe(
            self.node.submit_block(block, broadcast=True), loop)
        ok = submit.result(timeout=120)
        if ok:
            self.blocks_mined += 1


async def _noop():
    return None

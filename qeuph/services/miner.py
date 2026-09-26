"""
Solo miner service.

Runs one or more dedicated worker threads that:
  1. asks the ChainManager for a block template (coinbase + best mempool txs)
  2. grinds the 16-byte header nonce with double SHA3-512
  3. submits the won block to the node for validation + relay

Ported from QRL's core/Miner.py + MiningAPIService into a multi-threaded,
responsive service. `hashrate()` reports real-time sliding-window hashes per second.
"""
from __future__ import annotations

import asyncio
import collections
import os
import threading
import time
from typing import List, Optional

from qeuph import constants as C
from qeuph.core import pow as pow_mod


class SoloMiner:
    def __init__(self, node, threads: int = 1):
        self.node = node
        self.threads = max(1, threads)
        self._threads: List[threading.Thread] = []
        self._running = threading.Event()
        self._payout: Optional[bytes] = None   # addr hash
        self._hash_count = 0
        self._hash_start: Optional[float] = None
        self._recent_hashes: collections.deque = collections.deque(maxlen=40)
        self._lock = threading.Lock()
        self.blocks_mined = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ------------------------------------------------------------------
    def set_payout(self, addr_hash: bytes):
        self._payout = addr_hash

    def set_threads(self, count: int):
        was_running = self.is_mining()
        if was_running:
            self.stop()
        self.threads = max(1, min(16, count))
        if was_running:
            self.start()

    @property
    def payout_address_hex(self) -> Optional[str]:
        if self._payout is None:
            return None
        from qeuph.crypto.address import hash_to_address
        return hash_to_address(self._payout, self.node.network.hrp)

    def start(self, threads: Optional[int] = None):
        if self._running.is_set():
            return
        if self._payout is None:
            raise ValueError("payout address not set")
        if threads is not None:
            self.threads = max(1, min(16, threads))

        self._running.set()
        now = time.time()
        self._hash_start = now
        with self._lock:
            self._recent_hashes.clear()
            self._recent_hashes.append((now, self._hash_count))

        self._threads = []
        for i in range(self.threads):
            t = threading.Thread(target=self._worker_loop, args=(i, self.threads),
                                 daemon=True, name=f"qeuph-miner-{i}")
            self._threads.append(t)
            t.start()

    def stop(self):
        self._running.clear()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()

    def is_mining(self) -> bool:
        return self._running.is_set()

    def hashrate(self) -> float:
        if not self._running.is_set() or self._hash_start is None:
            return 0.0
        now = time.time()
        with self._lock:
            # prune entries older than 6.0s
            while self._recent_hashes and (now - self._recent_hashes[0][0]) > 6.0:
                self._recent_hashes.popleft()
            if len(self._recent_hashes) >= 2:
                dt = self._recent_hashes[-1][0] - self._recent_hashes[0][0]
                dh = self._recent_hashes[-1][1] - self._recent_hashes[0][1]
                if dt >= 0.5:
                    return max(0.0, dh / dt)
        dt = now - self._hash_start
        return self._hash_count / dt if dt > 0 else 0.0

    def _record_batch(self, count: int):
        with self._lock:
            self._hash_count += count
            now = time.time()
            self._recent_hashes.append((now, self._hash_count))

    # ------------------------------------------------------------------
    @property
    def node_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        return self._loop

    def attach_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    # ------------------------------------------------------------------
    def _worker_loop(self, worker_id: int, num_workers: int):
        loop = self._loop
        while self._running.is_set():
            try:
                self._mine_one(loop, worker_id, num_workers)
            except Exception:
                time.sleep(0.2)

    def _mine_one(self, loop, worker_id: int, num_workers: int):
        chain = self.node.chain
        mempool = self.node.mempool
        try:
            txs = mempool.best_transactions(C.MAX_BLOCK_SIZE - 200_000)
        except Exception:
            txs = []
        block, reward = chain.create_block_template(self._payout, txs)
        target = pow_mod.bits_to_target(block.header.bits)
        base = block.header.serialize()
        prefix = base[:-16]

        # Randomize nonce base per round to prevent collisions
        import random
        base_nonce = (random.getrandbits(32) << 32) | (random.getrandbits(32))

        step = num_workers
        nonce = base_nonce + worker_id
        batch_size = 512
        attempts = 0
        max_attempts = 1 << 28
        found = None

        while attempts < max_attempts and self._running.is_set():
            tried = 0
            found = None
            for _ in range(batch_size):
                blob = prefix + nonce.to_bytes(16, "little")
                if int.from_bytes(pow_mod.dhash(blob), "big") < target:
                    found = nonce
                    tried += 1
                    break
                nonce = (nonce + step) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
                tried += 1
            attempts += tried
            self._record_batch(tried)

            if found is not None:
                break

            # Check if block was already found by another thread/peer
            if chain.tip.hash != block.header.prev_hash:
                break

        if found is None:
            return

        block.header.nonce = found
        block.header._hash_cache = None
        if loop is not None:
            submit = asyncio.run_coroutine_threadsafe(
                self.node.submit_block(block, broadcast=True), loop)
            try:
                ok = submit.result(timeout=120)
                if ok:
                    with self._lock:
                        self.blocks_mined += 1
            except Exception:
                pass
        else:
            # Sync submit fallback
            result = chain.connect_block(block)
            if result.connected:
                with self._lock:
                    self.blocks_mined += 1
                mempool.on_new_block(block)

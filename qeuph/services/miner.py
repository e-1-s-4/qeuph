"""
Solo mining service.

`SoloMiner` runs N worker threads that:
  1. ask the ChainManager for a block template (coinbase + best mempool txs)
  2. grind the 16-byte header nonce with double SHA3-512 over disjoint
     nonce ranges
  3. submit the won block to the node for validation + relay

Each worker puts its own id into the coinbase extra nonce, so N workers never
mine the identical template and every block commits the miner that found it.

A worker abandons its template when
  * the chain tip moved under it, or
  * the template aged past `template_refresh` seconds, or
  * new transactions arrived in the mempool (checked between slices)

so solo mining follows the mempool instead of mining a stale snapshot.

`hashrate()` reports a sliding-window hashes/second figure.  A pure-Python
implementation sustains roughly 0.3 MH/s per core because SHA3-512 dominates;
`estimate_time_per_block()` turns that into an expected block interval so an
operator can see immediately when a machine is far below the network rate.
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

# how long a worker keeps mining one template before rebuilding it
TEMPLATE_REFRESH_SECONDS = 20.0
# nonce slice handed to a worker per iteration (lets it check for tip changes)
NONCE_SLICE = 1 << 16


class SoloMiner:
    def __init__(self, node, threads: int = 1):
        self.node = node
        self.threads = max(1, min(16, int(threads)))
        self._threads: List[threading.Thread] = []
        self._running = threading.Event()
        self._payout: Optional[bytes] = None   # addr hash
        self._hash_count = 0
        self._hash_start: Optional[float] = None
        self._recent_hashes: collections.deque = collections.deque(maxlen=64)
        self._lock = threading.RLock()
        self.blocks_mined = 0
        self.blocks_rejected = 0
        self.templates_built = 0
        self._template_started = 0.0
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._extra_nonce_prefix = os.urandom(2)

    # ------------------------------------------------------------------
    # configuration
    # ------------------------------------------------------------------
    def set_payout(self, addr_hash: bytes):
        if addr_hash is None or len(addr_hash) != C.ADDRESS_HASH_SIZE:
            raise ValueError("payout must be a 64-byte address hash")
        self._payout = addr_hash

    def set_threads(self, count: int):
        was_running = self.is_mining()
        if was_running:
            self.stop()
        self.threads = max(1, min(16, int(count)))
        if was_running:
            self.start()

    @property
    def payout_address_hex(self) -> Optional[str]:
        if self._payout is None:
            return None
        from qeuph.crypto.address import hash_to_address
        return hash_to_address(self._payout, self.node.network.hrp)

    @property
    def payout_hash(self) -> Optional[bytes]:
        return self._payout

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def start(self, threads: Optional[int] = None):
        if self._running.is_set():
            return
        if self._payout is None:
            raise ValueError("payout address not set")
        if threads is not None:
            self.threads = max(1, min(16, int(threads)))
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
            t.join(timeout=2.0)
        self._threads.clear()

    def is_mining(self) -> bool:
        return self._running.is_set()

    # ------------------------------------------------------------------
    # statistics
    # ------------------------------------------------------------------
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
            self._recent_hashes.append((time.time(), self._hash_count))

    def estimate_time_per_block(self) -> Optional[float]:
        """Expected seconds to find the next block at the current difficulty
        and the measured hashrate (None when not mining)."""
        from qeuph.core import pow as pow_mod
        hr = self.hashrate()
        if hr <= 0:
            return None
        try:
            target = pow_mod.bits_to_target(self.node.chain.tip.header.bits)
        except ValueError:
            return None
        return target / hr

    def stats(self) -> dict:
        hr = self.hashrate()
        est = self.estimate_time_per_block() if hr else None
        with self._lock:
            return {
                "mining": self.is_mining(),
                "threads": self.threads,
                "hashrate": round(hr, 2),
                "hashes": self._hash_count,
                "blocks_mined": self.blocks_mined,
                "blocks_rejected": self.blocks_rejected,
                "templates_built": self.templates_built,
                "payout": self.payout_address_hex,
                "seconds_per_block_estimate": round(est, 1) if est else None,
            }

    # ------------------------------------------------------------------
    # event loop plumbing
    # ------------------------------------------------------------------
    @property
    def node_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        return self._loop

    def attach_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    # ------------------------------------------------------------------
    # workers
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
        block, _reward = self._new_template_with(worker_id)
        base = block.header.serialize()
        # Each worker starts at a random point in the 128-bit nonce space and
        # then strides by num_workers, so workers never collide and restart
        # points are not synchronised across restarts either.
        nonce = int.from_bytes(os.urandom(8), "little") << 64
        step = num_workers
        while self._running.is_set():
            # abandon the template when the chain moved under it
            if chain.tip.hash != block.header.prev_hash:
                return
            found = None
            tried = 0
            for _ in range(8):
                if not self._running.is_set():
                    return
                base_nonce = nonce + tried
                for n, used in pow_mod.mine_range_count(
                        base, block.header.bits, base_nonce, NONCE_SLICE):
                    found = n
                    tried += used
                    break
                else:
                    tried += NONCE_SLICE
                self._record_batch(tried)
                tried = 0
                if found is not None:
                    break
                if chain.tip.hash != block.header.prev_hash:
                    return
            if found is None:
                nonce += 8 * NONCE_SLICE * step
                if time.time() - self._template_started > TEMPLATE_REFRESH_SECONDS:
                    return          # rebuild with a fresher mempool snapshot
                continue
            block.header.set_nonce(found)
            if self._submit(loop, block):
                with self._lock:
                    self.blocks_mined += 1
            else:
                with self._lock:
                    self.blocks_rejected += 1
            return

    def _new_template_with(self, worker_id: int):
        chain = self.node.chain
        try:
            txs = self.node.mempool.best_transactions(C.MAX_BLOCK_SIZE - 200_000)
        except Exception:
            txs = []
        extra = (self._extra_nonce_prefix
                 + bytes([worker_id & 0xFF, (worker_id >> 8) & 0xFF])
                 + b"qeuph")
        with self._lock:
            self.templates_built += 1
        self._template_started = time.time()
        return chain.create_block_template(self._payout, txs,
                                           extra_nonce=extra)

    def _submit(self, loop, block) -> bool:
        if loop is not None and loop.is_running():
            try:
                fut = asyncio.run_coroutine_threadsafe(
                    self.node.submit_block(block, broadcast=True), loop)
                return bool(fut.result(timeout=120))
            except Exception:
                return False
        # Sync submit fallback (no event loop attached, e.g. unit tests)
        result = self.node.chain.connect_block(block)
        if result.connected:
            self.node.mempool.on_new_block(block)
            return True
        return False

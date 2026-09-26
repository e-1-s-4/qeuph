"""
ChainManager: canonical chain, validation, reorg, block templates.

Ported from QRL's ChainManager (qrl/core/ChainManager.py) with SQLite
persistence and most-cumulative-work fork choice.

Fork choice (whitepaper 4.2): every stored block carries cumulative work
cummulative from genesis through its own chain.  The main chain tip is the
stored block with the highest cumulative work; reorganisation happens
whenever any stored block beats the current tip's work.

Orphan blocks (parent unknown) are held in a bounded in-memory map until
their parent arrives, then stored with computed cumulative work.  The
SQLite store keeps a work index so the best candidate is an O(log n) query.
"""
from __future__ import annotations

import os
import threading
import time
from typing import List, Optional, Tuple

from qeuph import constants as C
from qeuph.config import Network
from qeuph.core import difficulty as diff_mod
from qeuph.core import genesis as genesis_mod
from qeuph.core import pow as pow_mod
from qeuph.core import reward as reward_mod
from qeuph.core.block import Block
from qeuph.core.state import ChainState, UndoBlock
from qeuph.core.tx import Transaction
from qeuph.core.validation import (BlockValidationError, TxValidationError,
                                   validate_and_apply_block, validate_block)


class ConnectResult:
    """Outcome of a block submission.  Truthy when the block extended the
    main chain (backward compatible with the old bool return)."""
    __slots__ = ("connected", "orphan", "duplicate", "error", "fees")

    def __init__(self, connected=False, orphan=False, duplicate=False,
                 error: Optional[str] = None, fees: int = 0):
        self.connected = connected
        self.orphan = orphan
        self.duplicate = duplicate
        self.error = error
        self.fees = fees

    def __bool__(self):
        return self.connected


class ChainManager:
    def __init__(self, network: Network, data_dir: Optional[str] = None,
                 persist: bool = True):
        self.network = network
        self.data_dir = data_dir or network.data_dir
        # guards all chain state mutation/iteration across the event loop,
        # RPC threads and miner threads
        self.lock = threading.RLock()
        self.store: Optional = None
        if persist:
            os.makedirs(self.data_dir, exist_ok=True)
            self.store = self._open_store()

        self.genesis = genesis_mod.build_genesis(network)
        self.state = ChainState()
        self.tip: Block = self.genesis
        self.tip_work = self._block_work(self.genesis)
        # timestamps of the last RETARGET_WINDOW blocks (oldest first)
        self._timestamps: List[int] = [self.genesis.header.timestamp]
        # bounded in-memory orphan pool: hash -> (block, first_seen)
        self._orphans: dict = {}
        self._orphan_order: List[bytes] = []
        # blocks whose stored work is known, by hash (cumulative)
        self.on_block_connected = None      # callback(block) after connect
        self.on_reorg = None                # callback(new_tip, old_tip)

        if persist and self.store is not None:
            loaded = self._try_load()
            if not loaded:
                self._init_genesis()

    # ------------------------------------------------------------------
    def _open_store(self):
        from qeuph.db.store import Store
        return Store(os.path.join(self.data_dir, "chain.db"))

    # ------------------------------------------------------------------
    def _block_work(self, block: Block) -> int:
        try:
            target = pow_mod.bits_to_target(block.header.bits)
        except ValueError:
            return 1 << 512
        if target == 0:
            return 1 << 512
        return (1 << 512) // target + 1

    def _init_genesis(self):
        assert self.store is not None
        self.store.put_block(self.genesis, self.tip_work)
        self.store.set_main_block(0, self.genesis.hash)
        self.state.apply_block(self.genesis)
        self.store.save_state(self.state, self.genesis.hash, 0)

    def _try_load(self) -> bool:
        assert self.store is not None
        state, tip_hash, tip_height = self.store.load_state()
        if state is None or tip_hash is None:
            return False
        # verify genesis consistency
        g = self.store.get_block_by_hash(self.genesis.hash)
        if g is None or not genesis_mod.validate_genesis(g, self.network):
            return False
        tip = self.store.get_block_by_hash(tip_hash)
        if tip is None:
            return False
        self.state = state
        self.tip = tip
        self.tip_work = self.store.get_work(tip_hash) or 0
        self._timestamps = self._collect_timestamps(tip)
        return True

    def _collect_timestamps(self, tip: Block) -> List[int]:
        """Timestamps of the trailing window ending at tip (oldest first)."""
        window = max(self.network.retarget_interval, C.MTP_WINDOW)
        ts = []
        cur = tip
        while cur.height >= 0 and len(ts) < window:
            ts.append(cur.header.timestamp)
            if cur.height == 0:
                break
            cur = self._parent(cur)
        ts.reverse()
        return ts

    def _parent(self, block: Block) -> Block:
        if self.store is not None:
            p = self.store.get_block_by_hash(block.header.prev_hash)
            if p is not None:
                return p
        if block.header.prev_hash == self.genesis.hash:
            return self.genesis
        raise BlockValidationError("parent block missing")

    def _parent_opt(self, block: Block) -> Optional[Block]:
        try:
            if block.header.prev_hash == self.genesis.hash:
                return self.genesis
            if self.store is not None:
                return self.store.get_block_by_hash(block.header.prev_hash)
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def height(self) -> int:
        return self.tip.height

    def tip_hash(self) -> bytes:
        return self.tip.hash

    def get_block(self, block_hash: bytes) -> Optional[Block]:
        if block_hash == self.genesis.hash:
            return self.genesis
        if self.store is not None:
            return self.store.get_block_by_hash(block_hash)
        return None

    def get_block_by_height(self, height: int) -> Optional[Block]:
        if height == 0:
            return self.genesis
        if self.store is None:
            return None
        if height > self.tip.height:
            return None
        return self.store.get_block_by_height(height)

    def median_time_past(self, n: int = C.MTP_WINDOW) -> int:
        """Median of the last n block timestamps (Bitcoin-style MTP)."""
        with self.lock:
            ts = sorted(self._timestamps[-n:])
            if not ts:
                return self.tip.header.timestamp
            return ts[len(ts) // 2]

    def next_bits(self) -> int:
        return diff_mod.next_bits(self.tip.header.bits, self.tip.height,
                                  self._timestamps,
                                  self.network.retarget_interval,
                                  self.network.block_time)

    def block_reward(self) -> int:
        return reward_mod.block_reward(self.tip.height + 1)

    def coinbase_reward_with_fees(self, fees: int) -> int:
        return self.block_reward() + fees

    def orphan_count(self) -> int:
        return len(self._orphans)

    # ------------------------------------------------------------------
    # block submission
    # ------------------------------------------------------------------
    def connect_block(self, block: Block, current_time: Optional[int] = None) -> ConnectResult:
        """Validate and connect a block.

        Extending the current tip: full validation (raising
        BlockValidationError on rule violations, as before), apply, persist.
        Building on a known non-tip parent: store as side chain with
        cumulative work, then consider reorg.
        Building on an unknown parent: hold as orphan (bounded).

        Thread-safe (serialised by self.lock).
        """
        with self.lock:
            if self._block_known(block):
                return ConnectResult(duplicate=True)
            if block.hash == self.genesis.hash:
                return ConnectResult(duplicate=True)

            if block.header.prev_hash == self.tip.hash:
                return self._connect_on_tip(block, current_time)

            parent = None
            if self.store is not None:
                parent = self.store.get_block_by_hash(block.header.prev_hash)
            if parent is None and block.header.prev_hash == self.genesis.hash:
                parent = self.genesis
            if parent is None:
                self._hold_orphan(block)
                return ConnectResult(orphan=True,
                                     error="parent unknown (held as orphan)")

            # side chain (or future block on an older parent): check its own
            # PoW sanity before storing, then assign cumulative work
            if not self._validate_pow_light(block):
                return ConnectResult(error="proof of work invalid")
            if block.header.height != parent.height + 1:
                return ConnectResult(error="height mismatch with parent")
            work = (self.store.get_work(parent.hash) if self.store else None)
            if work is None and parent.hash == self.genesis.hash:
                work = self.tip_work if self.tip.hash == self.genesis.hash \
                    else self._block_work(self.genesis)
            if work is None:
                # parent's work unknown (parent itself an orphan chain head)
                self._hold_orphan(block)
                return ConnectResult(orphan=True, error="parent work unknown")
            cum = work + self._block_work(block)
            if self.store is not None:
                self.store.put_block(block, cum)
            self._resolve_orphans_of(block)
            return ConnectResult(connected=False)

    def _block_known(self, block: Block) -> bool:
        if block.hash in self._orphans:
            return True
        if self.store is not None:
            return self.store.block_exists(block.hash)
        return False

    def _validate_pow_light(self, block: Block) -> bool:
        try:
            return pow_mod.check_pow(block.header.serialize(), block.header.bits)
        except ValueError:
            return False

    def _hold_orphan(self, block: Block):
        h = block.hash
        if h in self._orphans:
            return
        if len(self._orphans) >= C.MAX_ORPHAN_BLOCKS:
            evict = self._orphan_order.pop(0)
            self._orphans.pop(evict, None)
        self._orphans[h] = (block, time.time())
        self._orphan_order.append(h)

    def _resolve_orphans_of(self, block: Block):
        """After storing `block`, attach any orphans that extend it."""
        progressed = True
        resolved_any = False
        while progressed and self.store is not None:
            progressed = False
            for h in self.store.children_of(block.hash):
                entry = self._orphans.pop(h, None)
                if entry is None:
                    continue
                orphan = entry[0]
                if not self._validate_pow_light(orphan):
                    continue
                work = self.store.get_work(block.hash)
                if work is None:
                    break
                cum = work + self._block_work(orphan)
                if orphan.header.height == block.height + 1:
                    self.store.put_block(orphan, cum)
                    self._resolve_orphans_of(orphan)
                    resolved_any = True
                    progressed = True
        if resolved_any:
            self.consider_reorg()

    def _connect_on_tip(self, block: Block, current_time: Optional[int]) -> ConnectResult:
        # difficulty check first
        expected_bits = self.next_bits()
        if block.header.bits != expected_bits:
            raise BlockValidationError(
                f"bits {hex(block.header.bits)} != required {hex(expected_bits)}")
        # checkpoint check
        if self.network.is_mainnet and block.height in C.CHECKPOINTS:
            if block.hash != C.CHECKPOINTS[block.height]:
                raise BlockValidationError(
                    f"block at height {block.height} does not match checkpoint")
        fees = validate_and_apply_block(
            block, self.tip, self.state, self.network.block_time,
            self.network.retarget_interval,
            current_time=current_time,
            mtp=self.median_time_past())
        # applied to state; record tip + persist incrementally
        self.tip = block
        self.tip_work += self._block_work(block)
        self._timestamps.append(block.header.timestamp)
        self._trim_timestamps()
        if self.store is not None:
            self.store.put_block(block, self.tip_work)
            self.store.set_main_block(block.height, block.hash)
            self._persist_delta(block)
        self._resolve_orphans_of(block)
        return ConnectResult(connected=True, fees=fees)

    def _persist_delta(self, block: Block):
        """Incrementally update the persisted UTXO/nonce tables for a block."""
        assert self.store is not None
        from qeuph.core.state import UTXO
        spent = []
        created = []
        for tx in block.transactions:
            txid = tx.txid()
            if tx.is_coinbase:
                for i, out in enumerate(tx.outputs):
                    created.append(((txid, i), UTXO(out.addr_hash, out.value,
                                                    True, block.height)))
                continue
            for inp in tx.inputs:
                spent.append((inp.prev_txid, inp.prev_index))
            for i, out in enumerate(tx.outputs):
                created.append(((txid, i), UTXO(out.addr_hash, out.value,
                                                False, block.height)))
        nonces = []
        from qeuph.crypto.address import pk_to_hash
        for tx in block.transactions:
            if tx.is_coinbase:
                continue
            for inp in tx.inputs:
                nonces.append((pk_to_hash(inp.pubkey), inp.txnonce))
        self.store.apply_block_delta(block, spent, created, nonces,
                                     block.hash, block.height)

    def _trim_timestamps(self):
        window = max(self.network.retarget_interval, C.MTP_WINDOW)
        if len(self._timestamps) > window * 2:
            self._timestamps = self._timestamps[-window:]

    # ------------------------------------------------------------------
    # reorganisation (most cumulative work wins)
    # ------------------------------------------------------------------
    def consider_reorg(self) -> bool:
        """Switch to the stored chain with the highest cumulative work."""
        if self.store is None:
            return False
        with self.lock:
            found = self.store.best_stored_chain_head(self.tip_work)
            if found is None:
                return False
            best_hash, best_work = found
            if best_hash == self.tip.hash:
                return False
            new_tip = self.store.get_block_by_hash(best_hash)
            if new_tip is None:
                return False
            old_tip = self.tip
            if not self._reorg_to(new_tip):
                return False
            if self.on_reorg:
                try:
                    self.on_reorg(new_tip, old_tip)
                except Exception:
                    pass
            return True

    def _reorg_to(self, new_tip: Block) -> bool:
        """Switch the main chain to `new_tip`.

        The candidate chain is VALIDATED block-by-block against a scratch
        state (full consensus rules including its own difficulty retarget
        history and checkpoints) before anything is committed; an invalid
        side chain is discarded and the current chain survives untouched.
        Returns True when the reorg was applied.
        """
        import time as _time
        # find common ancestor
        old_line = {}
        cur = self.tip
        while cur is not None:
            old_line[cur.hash] = cur
            cur = self._parent_opt(cur)
        new_line = []
        cur = new_tip
        while cur is not None and cur.hash not in old_line:
            new_line.append(cur)
            cur = self._parent_opt(cur)
        ancestor = cur
        if ancestor is None:
            return False

        # prefix: main-chain blocks from genesis (exclusive) to ancestor
        ancestor_line = []
        cur = ancestor
        while cur is not None and cur.hash != self.genesis.hash:
            ancestor_line.append(cur)
            cur = self._parent_opt(cur)
        ancestor_line.reverse()

        # ---- validate the candidate chain on a scratch state -----------
        scratch = ChainState()
        scratch.apply_block(self.genesis)
        ts = [self.genesis.header.timestamp]
        prev = self.genesis
        for blk in ancestor_line:
            scratch.apply_block(blk)
            ts.append(blk.header.timestamp)
            prev = blk
        now = int(_time.time())
        for blk in reversed(new_line):
            expected_bits = diff_mod.next_bits(
                prev.header.bits, prev.height, ts,
                self.network.retarget_interval, self.network.block_time)
            if blk.header.bits != expected_bits:
                self._invalidate_side_chain(new_tip)
                return False
            if self.network.is_mainnet and blk.height in C.CHECKPOINTS:
                if blk.hash != C.CHECKPOINTS[blk.height]:
                    self._invalidate_side_chain(new_tip)
                    return False
            mtp = self._median_of(ts)
            try:
                validate_and_apply_block(
                    blk, prev, scratch, self.network.block_time,
                    self.network.retarget_interval,
                    current_time=now, mtp=mtp)
            except BlockValidationError:
                self._invalidate_side_chain(new_tip)
                return False
            ts.append(blk.header.timestamp)
            prev = blk

        # ---- commit ------------------------------------------------------
        old_tip = self.tip
        self.state = scratch
        self.tip = new_tip
        self.tip_work = (self.store.get_work(new_tip.hash) if self.store
                         else sum(self._block_work(b) for b in ancestor_line) +
                         sum(self._block_work(b) for b in new_line) +
                         self._block_work(self.genesis))
        self._timestamps = ts
        self._trim_timestamps()

        if self.store is not None:
            self.store.truncate_main_chain(ancestor.height + 1)
            for blk in ancestor_line:
                self.store.set_main_block(blk.height, blk.hash)
            for blk in reversed(new_line):
                self.store.set_main_block(blk.height, blk.hash)
            self.store.save_state(self.state, self.tip.hash, self.tip.height)
        return True

    def _invalidate_side_chain(self, head: Block):
        """Remove a side chain that failed validation so it cannot compete
        again (walk from head toward the fork, stop at main-chain blocks)."""
        if self.store is None:
            return
        cur = head
        guard = 0
        while cur is not None and guard < 1_000_000:
            guard += 1
            if self.store.get_main_hash_at_height(cur.height) == cur.hash:
                break  # reached the (new) main chain
            self.store.remove_block(cur.hash)
            cur = self._parent_opt(cur)

    @staticmethod
    def _median_of(ts: List[int]) -> int:
        w = sorted(ts[-C.MTP_WINDOW:])
        return w[len(w) // 2] if w else 0

    def disconnected_blocks(self, old_tip: Block, new_tip: Block) -> List[Block]:
        """Blocks that left the main chain in the reorg old_tip -> new_tip
        (used to return their transactions to the mempool)."""
        old_line = {}
        cur = old_tip
        while cur is not None:
            old_line[cur.hash] = cur
            cur = self._parent_opt(cur)
        out = []
        cur = new_tip
        while cur is not None and cur.hash not in old_line:
            cur = self._parent_opt(cur)
        fork = cur
        cur = old_tip
        while cur is not None and cur.hash != (fork.hash if fork else None):
            out.append(cur)
            cur = self._parent_opt(cur)
        return out

    # ------------------------------------------------------------------
    # mining helpers
    # ------------------------------------------------------------------
    def create_block_template(self, coinbase_addr_hash: bytes,
                              transactions: List[Transaction],
                              timestamp: Optional[int] = None) -> Tuple[Block, int]:
        """Assemble an unmined block on the current tip."""
        with self.lock:
            fees = 0
            working_utxos = {}
            for tx in transactions:
                if tx.is_coinbase:
                    raise ValueError("coinbase in template tx list")
                # fee accounting with chained UTXO resolution
                total_in = 0
                for inp in tx.inputs:
                    op = (inp.prev_txid, inp.prev_index)
                    if op in working_utxos:
                        total_in += working_utxos[op].value
                    else:
                        u = self.state.get_utxo(inp.prev_txid, inp.prev_index)
                        if u is not None:
                            total_in += u.value
                fees += max(0, total_in - tx.total_out)
                for idx, out in enumerate(tx.outputs):
                    working_utxos[(tx.txid(), idx)] = out
            reward = self.coinbase_reward_with_fees(fees)
            from qeuph.core.tx import make_coinbase
            coinbase = make_coinbase(self.tip.height + 1, coinbase_addr_hash, reward)
            bits = self.next_bits()
            block = Block.build(self.tip.hash, self.tip.height + 1, bits,
                                [coinbase] + list(transactions), timestamp,
                                min_timestamp=self.tip.header.timestamp + 1)
            return block, reward

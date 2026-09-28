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

import logging
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
from qeuph.core.validation import BlockValidationError, validate_and_apply_block

logger = logging.getLogger("qeuph.chain")


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
                 persist: bool = True, state: Optional[ChainState] = None):
        self.network = network
        self.data_dir = data_dir or network.data_dir
        # guards all chain state mutation/iteration across the event loop,
        # RPC threads and miner threads
        self.lock = threading.RLock()
        self.persist = persist
        self.store: Optional = None
        if persist:
            os.makedirs(self.data_dir, exist_ok=True)
            self.store = self._open_store()

        self.genesis = genesis_mod.build_genesis(network)
        # The ChainState object identity is NOT stable: a reorganisation
        # rebuilds it from the fork point.  Every collaborator must therefore
        # reach it through `chain.state` (or `chain.state_provider()`), never
        # by caching the object it saw at construction time.
        self.state: ChainState = state if state is not None else ChainState()
        self.tip: Block = self.genesis
        self.tip_work = self._block_work(self.genesis)
        # timestamps of the last RETARGET_WINDOW blocks (oldest first)
        self._timestamps: List[int] = [self.genesis.header.timestamp]
        # bounded in-memory orphan pool: hash -> (block, first_seen)
        self._orphans: dict = {}
        self._orphan_order: List[bytes] = []
        self.on_block_connected = None      # callback(block) after connect
        self.on_reorg = None                # callback(new_tip, old_tip)
        self.reorg_count = 0
        self.blocks_connected = 0
        self.orphans_rejected = 0

        if persist and self.store is not None:
            if not self._try_load():
                self._init_genesis()

    # ------------------------------------------------------------------
    def state_provider(self):
        """Return a callable yielding the CURRENT ChainState (reorg-safe)."""
        return lambda: self.state

    def _open_store(self):
        from qeuph.db.store import Store
        return Store(os.path.join(self.data_dir, "chain.db"))

    def close(self):
        if self.store is not None:
            self.store.close()
            self.store = None

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
        self.state = ChainState()
        self.state.apply_block(self.genesis)
        self.tip = self.genesis
        self.tip_work = self._block_work(self.genesis)
        self._timestamps = [self.genesis.header.timestamp]
        self._orphans.clear()
        del self._orphan_order[:]
        self.store.init_genesis(self.genesis, self.tip_work, self.state)

    def _try_load(self) -> bool:
        """Load persisted state, self-healing a damaged canonical index."""
        assert self.store is not None
        state, tip_hash, tip_height = self.store.load_state()
        if state is None or tip_hash is None:
            self._refuse_foreign_store()
            return False
        ok, why = self.store.verify_main_chain(self.genesis.hash)
        if not ok:
            self._refuse_foreign_store()
            logger.warning("canonical index inconsistent (%s); replaying from "
                           "genesis", why)
            self._replay_main_chain()
            state, tip_hash, tip_height = self.store.load_state()
            if state is None or tip_hash is None:
                return False
        g = self.store.get_block_by_hash(self.genesis.hash)
        if g is None or not genesis_mod.validate_genesis(g, self.network):
            return False
        tip = self.store.get_block_by_hash(tip_hash)
        if tip is None or tip.height != tip_height:
            return False
        self.state = state
        self.tip = tip
        self.tip_work = self.store.get_work(tip_hash) or self._block_work(tip)
        self._timestamps = self._collect_timestamps(tip)
        return True

    def _refuse_foreign_store(self):
        """Hard-stop when the data directory holds a DIFFERENT chain.

        A testnet daemon pointed at a regtest data dir (or any genesis
        mismatch) used to crash deep inside the replay with a raw
        AttributeError; a directory that holds blocks but not THIS network's
        genesis is by definition foreign, and no automatic replay can make
        it ours.  Refuse loudly instead.
        """
        if self.store.has_blocks() and \
                self.store.get_block_by_hash(self.genesis.hash) is None:
            raise SystemExit(
                f"data directory {self.data_dir} holds a different chain "
                f"(no {self.network.name} genesis block). Point --data-dir "
                f"at this network's directory or move the old one away.")

    def _replay_main_chain(self):
        """Rebuild UTXO/nonce tables by re-applying the canonical blocks.

        Only used when the index the incremental deltas were written against
        is damaged, so it is worth paying a full replay to get back to a state
        that is known to agree with the block index.
        """
        assert self.store is not None
        rows = self.store.raw_main_chain()
        state = ChainState()
        state.apply_block(self.genesis)
        prev = self.genesis
        good = [(0, self.genesis.hash)]
        for h, hsh in rows:
            if h == 0:
                continue
            if h != prev.height + 1:
                break
            blk = self.store.get_block_by_hash(hsh)
            if blk is None or blk.header.prev_hash != prev.hash:
                break
            state.apply_block(blk)
            good.append((h, hsh))
            prev = blk
        self.store.reorganize(good, state, prev.hash, prev.height)
        work = self._block_work(self.genesis)
        self.store.set_block_work(self.genesis.hash, work)
        for h, hsh in good:
            if h == 0:
                continue          # genesis work is already recorded above
            blk = self.store.get_block_by_hash(hsh)
            if blk is None:
                break             # defensive: never dereference a gap
            work += self._block_work(blk)
            self.store.set_block_work(hsh, work)

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

    def get_orphan(self, block_hash: bytes) -> Optional[Block]:
        entry = self._orphans.get(block_hash)
        return entry[0] if entry else None

    def orphan_hashes(self) -> List[bytes]:
        return list(self._orphans.keys())

    def chain_stats(self) -> dict:
        return {
            "height": self.height(),
            "tip": self.tip_hash().hex(),
            "work": self.tip_work,
            "blocks_connected": self.blocks_connected,
            "reorgs": self.reorg_count,
            "orphans": self.orphan_count(),
            "orphans_rejected": self.orphans_rejected,
            "stored_blocks": self.store.count_blocks() if self.store else 0,
            "utxos": len(self.state.utxos),
        }

    # ------------------------------------------------------------------
    # block submission
    # ------------------------------------------------------------------
    def connect_block(self, block: Block,
                      current_time: Optional[int] = None) -> ConnectResult:
        """Validate and connect a block.

        Extending the current tip: full validation (raising
        BlockValidationError on rule violations), apply, persist atomically.
        Building on a known non-tip parent: store as a side chain with
        cumulative work, then consider a reorg.
        Building on an unknown parent: hold as an orphan (bounded + expiring).

        Thread-safe (serialised by self.lock).
        """
        with self.lock:
            self._expire_orphans()
            if block.hash == self.genesis.hash:
                return ConnectResult(duplicate=True)
            if self._block_known(block):
                return ConnectResult(duplicate=True)

            if block.header.prev_hash == self.tip.hash:
                return self._connect_on_tip(block, current_time)

            parent = self._parent_opt(block)
            if parent is None:
                self._hold_orphan(block)
                return ConnectResult(orphan=True,
                                     error="parent unknown (held as orphan)")

            # side chain (or a future block on an older parent): check its own
            # PoW before storing, then assign cumulative work
            if not self._validate_pow_light(block):
                return ConnectResult(error="proof of work invalid")
            if block.header.height != parent.height + 1:
                return ConnectResult(error="height mismatch with parent")
            work = self.store.get_work(parent.hash) if self.store else None
            if work is None and parent.hash == self.genesis.hash:
                work = self._block_work(self.genesis)
            if work is None:
                # parent's cumulative work is unknown (its own parent chain is
                # incomplete): keep it until the parent chain fills in
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
        # never hold a block whose PoW is already known to be invalid
        if not self._validate_pow_light(block):
            self.orphans_rejected += 1
            return
        while len(self._orphans) >= C.MAX_ORPHAN_BLOCKS and self._orphan_order:
            evict = self._orphan_order.pop(0)
            self._orphans.pop(evict, None)
        self._orphans[h] = (block, time.time())
        self._orphan_order.append(h)

    def _expire_orphans(self):
        """Drop orphans nobody came back for."""
        now = time.time()
        while self._orphan_order:
            h = self._orphan_order[0]
            entry = self._orphans.get(h)
            if entry is None:
                self._orphan_order.pop(0)
                continue
            if now - entry[1] <= C.ORPHAN_EXPIRY:
                break
            self._orphan_order.pop(0)
            self._orphans.pop(h, None)

    def _resolve_orphans_of(self, block: Block):
        """After storing `block`, attach any orphans that extend it."""
        if self.store is None:
            return
        resolved_any = False
        queue = list(self.store.children_of(block.hash))
        seen = set()
        while queue:
            h = queue.pop(0)
            if h in seen:
                continue
            seen.add(h)
            entry = self._orphans.pop(h, None)
            if entry is None:
                continue
            if h in self._orphan_order:
                try:
                    self._orphan_order.remove(h)
                except ValueError:
                    pass
            orphan = entry[0]
            if not self._validate_pow_light(orphan):
                self.orphans_rejected += 1
                continue
            work = self.store.get_work(block.hash)
            if work is None:
                break
            if orphan.header.height != block.height + 1:
                continue
            self.store.put_block(orphan, work + self._block_work(orphan))
            resolved_any = True
            queue.extend(self.store.children_of(orphan.hash))
            block = orphan
        if resolved_any:
            self.consider_reorg()

    def _connect_on_tip(self, block: Block,
                       current_time: Optional[int]) -> ConnectResult:
        # difficulty check first
        expected_bits = self.next_bits()
        if block.header.bits != expected_bits:
            raise BlockValidationError(
                f"bits {hex(block.header.bits)} != required {hex(expected_bits)}")
        # checkpoint check
        pinned = self._checkpoint(block.height)
        if pinned is not None and block.hash != pinned:
            raise BlockValidationError(
                f"block at height {block.height} does not match checkpoint")
        undos: List[UndoBlock] = []
        fees = validate_and_apply_block(
            block, self.tip, self.state, self.network.block_time,
            self.network.retarget_interval,
            current_time=current_time,
            mtp=self.median_time_past(),
            undo_out=undos)
        # validation succeeded and the state now has the block applied
        try:
            self.tip = block
            self.tip_work += self._block_work(block)
            self._timestamps.append(block.header.timestamp)
            self._trim_timestamps()
            if self.store is not None:
                spent, created, nonces = self._block_delta(block)
                self.store.connect_block(block, self.tip_work, spent, created,
                                         nonces)
        except Exception:
            # persistence failed: roll the in-memory chain back so it still
            # agrees with the store, then propagate
            for undo in undos:
                self.state.undo_block(undo)
            self.tip = self._parent(block)
            self.tip_work -= self._block_work(block)
            if self._timestamps and self._timestamps[-1] == block.header.timestamp:
                self._timestamps.pop()
            raise
        self.blocks_connected += 1
        self._resolve_orphans_of(block)
        return ConnectResult(connected=True, fees=fees)

    def _checkpoint(self, height: int) -> Optional[bytes]:
        from qeuph.config import checkpoint_for
        return checkpoint_for(self.network, height)

    def _block_delta(self, block: Block):
        """(spent, created, nonces) rows describing this block's effect."""
        from qeuph.core.state import UTXO
        from qeuph.crypto.address import pk_to_hash
        spent = []
        created = []
        nonces = []
        for tx in block.transactions:
            txid = tx.txid()
            if tx.is_coinbase:
                for i, out in enumerate(tx.outputs):
                    if out.value <= 0:
                        continue
                    created.append(((txid, i), UTXO(out.addr_hash, out.value,
                                                    True, block.height)))
                continue
            for inp in tx.inputs:
                spent.append((inp.prev_txid, inp.prev_index))
                nonces.append((pk_to_hash(inp.pubkey), inp.txnonce))
            for i, out in enumerate(tx.outputs):
                if out.value <= 0:
                    continue
                created.append(((txid, i), UTXO(out.addr_hash, out.value,
                                                False, block.height)))
        return spent, created, nonces

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

        The commit is a single store transaction, and the previous in-memory
        state stays authoritative if persistence fails.  Because the state
        OBJECT is replaced, every collaborator must go through
        `chain.state` / `chain.state_provider()` - see `state_provider`.
        """
        # find common ancestor
        old_line = {}
        cur: Optional[Block] = self.tip
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
        now = int(time.time())
        for blk in reversed(new_line):
            expected_bits = diff_mod.next_bits(
                prev.header.bits, prev.height, ts,
                self.network.retarget_interval, self.network.block_time)
            if blk.header.bits != expected_bits:
                self._invalidate_side_chain(new_tip)
                return False
            pinned = self._checkpoint(blk.height)
            if pinned is not None and blk.hash != pinned:
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
        main_index = [(0, self.genesis.hash)]
        main_index += [(b.height, b.hash) for b in ancestor_line]
        main_index += [(b.height, b.hash) for b in reversed(new_line)]
        new_tip_work = (self.store.get_work(new_tip.hash) if self.store
                        else self._block_work(self.genesis)
                        + sum(self._block_work(b) for b in ancestor_line)
                        + sum(self._block_work(b) for b in new_line))
        if self.store is not None:
            try:
                self.store.reorganize(main_index, scratch, new_tip.hash,
                                      new_tip.height)
            except Exception:
                logger.exception("reorg persistence failed; keeping old chain")
                return False
        self.state = scratch
        self.tip = new_tip
        self.tip_work = new_tip_work
        self._timestamps = ts
        self._trim_timestamps()
        self.reorg_count += 1
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
                              timestamp: Optional[int] = None,
                              extra_nonce: bytes = b"") -> Tuple[Block, int]:
        """Assemble an unmined block on the current tip.

        `extra_nonce` is up to 256 bytes of miner-chosen coinbase data (the
        solo miner puts a per-worker counter there so parallel workers never
        mine identical templates).
        """
        from qeuph.core.tx import MAX_COINBASE_DATA, make_coinbase
        with self.lock:
            if len(coinbase_addr_hash) != C.ADDRESS_HASH_SIZE:
                raise ValueError("payout address hash must be 64 bytes")
            if len(extra_nonce) > MAX_COINBASE_DATA:
                raise ValueError("extra nonce too long")
            fees = 0
            working_utxos: dict = {}
            for tx in transactions:
                if tx.is_coinbase:
                    raise ValueError("coinbase in template tx list")
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
            if fees > (1 << 63):
                raise ValueError("absurd fee total")
            reward = self.coinbase_reward_with_fees(fees)
            coinbase = make_coinbase(self.tip.height + 1, coinbase_addr_hash,
                                     reward, data=extra_nonce)
            bits = self.next_bits()
            block = Block.build(self.tip.hash, self.tip.height + 1, bits,
                                [coinbase] + list(transactions), timestamp,
                                min_timestamp=self.tip.header.timestamp + 1)
            return block, reward

    # ------------------------------------------------------------------
    # maintenance
    # ------------------------------------------------------------------
    def reindex(self, prune: bool = True, drop_side: bool = True) -> dict:
        """Rebuild the canonical index and UTXO tables from the stored blocks.

        Returns a report dict.  Safe to run on a stopped node: the in-memory
        chain is left at the tip it had and the store is rewritten in one
        transaction per block so an interrupted reindex never leaves a
        half-rebuilt store (the caller re-runs it).
        """
        assert self.store is not None
        with self.lock:
            rows = self.store.raw_main_chain()
            report = {"blocks": 0, "pruned": 0, "dropped": 0, "tip": 0}
            state = ChainState()
            state.apply_block(self.genesis)
            self.store.init_genesis(self.genesis, self._block_work(self.genesis),
                                    state)
            work = self._block_work(self.genesis)
            prev = self.genesis
            ts = [self.genesis.header.timestamp]
            for h, hsh in rows:
                if h == 0:
                    continue
                if h != prev.height + 1:
                    break
                blk = self.store.get_block_by_hash(hsh)
                if blk is None or blk.header.prev_hash != prev.hash:
                    break
                validate_and_apply_block(
                    blk, prev, state, self.network.block_time,
                    self.network.retarget_interval,
                    current_time=None, mtp=self._median_of(ts))
                spent, created, nonces = self._block_delta(blk)
                work += self._block_work(blk)
                self.store.connect_block(blk, work, spent, created, nonces)
                report["blocks"] += 1
                ts.append(blk.header.timestamp)
                prev = blk
            if drop_side:
                report["dropped"] = self.store.drop_side_chains()
            elif prune:
                report["pruned"] = self.store.prune_side_chains()
            self.state = state
            self.tip = prev
            self.tip_work = work
            self._timestamps = self._collect_timestamps(prev)
            report["tip"] = prev.height
            return report

    def verify_chain(self, limit: Optional[int] = None) -> dict:
        """Re-validate the canonical chain from genesis against a scratch state.

        Used by `qeuph chain verify` and the test suite; a mismatch means the
        store must be reindexed.
        """
        assert self.store is not None
        with self.lock:
            state = ChainState()
            state.apply_block(self.genesis)
            prev = self.genesis
            ts = [prev.header.timestamp]
            checked = 0
            height = prev.height
            while limit is None or checked < limit:
                height += 1
                blk = self.store.get_block_by_height(height)
                if blk is None or height > self.tip.height:
                    break
                expected = diff_mod.next_bits(
                    prev.header.bits, prev.height, ts,
                    self.network.retarget_interval, self.network.block_time)
                if blk.header.bits != expected:
                    return {"ok": False, "height": height,
                            "error": f"bits {hex(blk.header.bits)} != "
                                      f"{hex(expected)}"}
                try:
                    validate_and_apply_block(
                        blk, prev, state, self.network.block_time,
                        self.network.retarget_interval,
                        current_time=None, mtp=self._median_of(ts))
                except BlockValidationError as e:
                    return {"ok": False, "height": height, "error": str(e)}
                ts.append(blk.header.timestamp)
                prev = blk
                checked += 1
            return {"ok": True, "checked": checked, "tip": prev.height}


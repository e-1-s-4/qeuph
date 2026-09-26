"""
ChainManager: canonical chain, validation, reorg, block templates.

Ported from QRL's ChainManager (qrl/core/ChainManager.py) with SQLite
persistence and most-cumulative-work fork choice.
"""
from __future__ import annotations

import os
import time
from typing import List, Optional, Tuple

from qeuph import constants as C
from qeuph.config import Network
from qeuph.core import difficulty as diff_mod
from qeuph.core import genesis as genesis_mod
from qeuph.core import pow as pow_mod
from qeuph.core import reward as reward_mod
from qeuph.core.block import Block
from qeuph.core.state import ChainState
from qeuph.core.tx import Transaction
from qeuph.core.validation import BlockValidationError, validate_block, validate_coinbase
from qeuph.db.store import Store


class ChainManager:
    def __init__(self, network: Network, data_dir: Optional[str] = None,
                 persist: bool = True):
        self.network = network
        self.data_dir = data_dir or network.data_dir
        self.store: Optional[Store] = None
        if persist:
            os.makedirs(self.data_dir, exist_ok=True)
            self.store = Store(os.path.join(self.data_dir, "chain.db"))

        self.genesis = genesis_mod.build_genesis(network)
        self.state = ChainState()
        self.tip: Block = self.genesis
        self.tip_work = self._block_work(self.genesis)
        self._timestamps: List[int] = [self.genesis.header.timestamp]

        if persist and self.store is not None:
            loaded = self._try_load()
            if not loaded:
                self._init_genesis()

    # ------------------------------------------------------------------
    def _block_work(self, block: Block) -> int:
        target = pow_mod.bits_to_target(block.header.bits)
        if target == 0:
            return 1 << 256
        return (1 << 512) // target + 1

    def _init_genesis(self):
        assert self.store is not None
        self.store.put_block(self.genesis, self.tip_work)
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
        ts = []
        cur = tip
        need = min(self.network.retarget_interval, cur.height + 1)
        while cur.height >= 0 and len(ts) < need:
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

    def next_bits(self) -> int:
        return diff_mod.next_bits(self.tip.header.bits, self.tip.height,
                                  self._timestamps,
                                  self.network.retarget_interval,
                                  self.network.block_time)

    def block_reward(self) -> int:
        return reward_mod.block_reward(self.tip.height + 1)

    def coinbase_reward_with_fees(self, fees: int) -> int:
        return self.block_reward() + fees

    # ------------------------------------------------------------------
    # block submission
    # ------------------------------------------------------------------
    def connect_block(self, block: Block, current_time: Optional[int] = None) -> bool:
        """Validate and connect a block extending the current tip.

        Returns True when connected.  Raises BlockValidationError otherwise.
        Blocks building on non-tip parents are stored for later (returns
        False) so the node can track side chains.
        """
        if block.header.prev_hash == self.tip.hash:
            fees = self._validate_and_apply(block, current_time)
            return True
        # side chain / orphan bookkeeping
        if self.store is not None and not self.store.block_exists(block.hash):
            if self._validate_pow_light(block):
                self.store.put_block(block, 0)
        return False

    def _validate_pow_light(self, block: Block) -> bool:
        try:
            return pow_mod.check_pow(block.header.serialize(), block.header.bits)
        except ValueError:
            return False

    def _validate_and_apply(self, block: Block, current_time: Optional[int]) -> int:
        # difficulty check first
        expected_bits = self.next_bits()
        if block.header.bits != expected_bits:
            raise BlockValidationError(
                f"bits {hex(block.header.bits)} != required {hex(expected_bits)}")
        # checkpoint check
        if self.network.is_mainnet and block.height in C.CHECKPOINTS:
            if block.hash != C.CHECKPOINTS[block.height]:
                raise BlockValidationError(
                    f"block at height {block.height} hash {block.hash.hex()} "
                    f"does not match checkpoint {C.CHECKPOINTS[block.height].hex()}")
        fees = validate_block(block, self.tip, self.state, self.network.block_time,
                              self.network.retarget_interval,
                              current_time=current_time)
        # apply
        self.state.apply_block(block)
        self.tip = block
        self.tip_work += self._block_work(block)
        self._timestamps.append(block.header.timestamp)
        if self.store is not None:
            self.store.put_block(block, self.tip_work)
            self.store.save_state(self.state, self.tip.hash, self.tip.height)
        return fees

    # ------------------------------------------------------------------
    # reorganisation (most cumulative work wins)
    # ------------------------------------------------------------------
    def consider_reorg(self) -> bool:
        """If a stored side chain has more work than the tip, reorganise."""
        if self.store is None:
            return False
        candidates = self.store.get_block_hashes_by_height(self.tip.height)
        # also consider longer chains one height above
        candidates += self.store.get_block_hashes_by_height(self.tip.height + 1)
        best_hash, best_work = None, self.tip_work
        for h in candidates:
            if h == self.tip.hash:
                continue
            w = self.store.get_work(h)
            if w is not None and w > best_work:
                best_hash, best_work = h, w
        if best_hash is None:
            return False
        new_tip = self.store.get_block_by_hash(best_hash)
        if new_tip is None:
            return False
        self._reorg_to(new_tip)
        return True

    def _reorg_to(self, new_tip: Block):
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
        # replay: rebuild state from ancestor through new_line
        self.state = ChainState()
        self.tip = ancestor if ancestor is not None else self.genesis
        self.tip_work = self.store.get_work(self.tip.hash) if self.store else 0
        self._timestamps = self._collect_timestamps(self.tip)
        for blk in reversed(new_line):
            self.state.apply_block(blk)
            self.tip = blk
            self.tip_work += self._block_work(blk)
            self._timestamps.append(blk.header.timestamp)
        if self.store is not None:
            self.store.save_state(self.state, self.tip.hash, self.tip.height)

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
    # mining helpers
    # ------------------------------------------------------------------
    def create_block_template(self, coinbase_addr_hash: bytes,
                              transactions: List[Transaction],
                              timestamp: Optional[int] = None) -> Tuple[Block, int]:
        """Assemble an unmined block on the current tip."""
        fees = 0
        for tx in transactions:
            if tx.is_coinbase:
                raise ValueError("coinbase in template tx list")
            # fee accounting done by the caller via mempool
            total_in = 0
            for inp in tx.inputs:
                u = self.state.get_utxo(inp.prev_txid, inp.prev_index)
                if u is not None:
                    total_in += u.value
            fees += total_in - tx.total_out
        reward = self.coinbase_reward_with_fees(fees)
        from qeuph.core.tx import make_coinbase
        coinbase = make_coinbase(self.tip.height + 1, coinbase_addr_hash, reward)
        bits = self.next_bits()
        block = Block.build(self.tip.hash, self.tip.height + 1, bits,
                            [coinbase] + list(transactions), timestamp,
                            min_timestamp=self.tip.header.timestamp + 1)
        return block, reward

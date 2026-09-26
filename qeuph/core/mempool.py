"""
Mempool: pending transactions awaiting block inclusion.

Ported from QRL's TransactionPool (qrl/core/TransactionPool.py) to the
UTXO + txnonce model.  Transactions are admitted only when they validate
against the confirmed chain state overlaid with already-pending spends,
which naturally enforces per-address nonce ordering inside the pool.

The admission fee is cached at insertion time (the overlay mutates as
txs enter, so fees cannot be recomputed later); block templates rank by
the cached fee-per-byte.  When the pool reaches its byte budget the
lowest-fee transactions are evicted first, and transactions older than
MEMPOOL_EVICT_AGE are dropped by the expiry sweep.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Tuple

from qeuph import constants as C
from qeuph.core.state import UTXO
from qeuph.core.tx import Transaction
from qeuph.core.validation import TxValidationError, validate_tx


class _StateView:
    """State-like object routing lookups through the mempool overlay."""

    __slots__ = ("_get_utxo", "_nonce_of")

    def __init__(self, get_utxo, nonce_of):
        self._get_utxo = get_utxo
        self._nonce_of = nonce_of

    def get_utxo(self, txid, idx):
        return self._get_utxo(txid, idx)

    def nonce_of(self, addr_hash):
        return self._nonce_of(addr_hash)


class Mempool:
    def __init__(self, state, fee_rate: int = C.MIN_RELAY_FEE_RATE,
                 height_fn=None, mtp_fn=None):
        self.state = state
        self.fee_rate = fee_rate
        self._height_fn = height_fn or (lambda: 0)
        self._mtp_fn = mtp_fn or (lambda: 0)
        self.lock = threading.RLock()
        self.txs: Dict[bytes, Transaction] = {}
        # admission-time fee + size + timestamp per txid
        self._fees: Dict[bytes, int] = {}
        self._sizes: Dict[bytes, int] = {}
        self._added_at: Dict[bytes, float] = {}
        # overlay: outpoint -> UTXO as it would be after pending txs
        self._overlay: Dict[Tuple[bytes, int], UTXO] = {}
        self._overlay_removed = set()
        # per-address pending nonce picture
        self._addr_pending_nonce: Dict[bytes, int] = {}

    # ------------------------------------------------------------------
    def _lookup(self, txid, idx):
        op = (txid, idx)
        if op in self._overlay_removed:
            return None
        if op in self._overlay:
            return self._overlay[op]
        return self.state.get_utxo(txid, idx)

    def _nonce_of(self, addr_hash: bytes) -> int:
        base = self.state.nonce_of(addr_hash)
        pend = self._addr_pending_nonce.get(addr_hash, base)
        return max(base, pend)

    def _view(self) -> _StateView:
        return _StateView(self._lookup, self._nonce_of)

    def _next_height(self) -> int:
        return self._height_fn() + 1

    # ------------------------------------------------------------------
    def add_tx(self, tx: Transaction) -> int:
        """Validate and admit a transaction.  Returns its fee."""
        if tx.is_coinbase:
            raise TxValidationError("coinbase cannot enter mempool")
        with self.lock:
            txid = tx.txid()
            if txid in self.txs:
                raise TxValidationError("transaction already in mempool")
            size = tx.size()
            if size > C.MAX_TX_SIZE:
                raise TxValidationError("transaction too large")
            if self.total_size() + size > C.MAX_MEMPOOL_SIZE:
                # try to evict lower-fee txs to make room
                if not self._evict_for(size):
                    raise TxValidationError("mempool full")

            # validate against state + overlay with mempool-aware nonce
            fee = validate_tx(tx, self._view(), height=self._next_height(),
                              fee_rate=self.fee_rate,
                              mtp=self._mtp_fn())

            # apply to overlay
            for inp in tx.inputs:
                op = (inp.prev_txid, inp.prev_index)
                self._overlay.pop(op, None)
                self._overlay_removed.add(op)
            from qeuph.crypto.address import pk_to_hash
            for inp in tx.inputs:
                self._addr_pending_nonce[pk_to_hash(inp.pubkey)] = inp.txnonce
            for i, out in enumerate(tx.outputs):
                self._overlay[(txid, i)] = UTXO(out.addr_hash, out.value, False, 0)
            self.txs[txid] = tx
            self._fees[txid] = fee
            self._sizes[txid] = size
            self._added_at[txid] = time.time()
            return fee

    # ------------------------------------------------------------------
    def get_fee(self, txid: bytes) -> Optional[int]:
        """Cached admission fee for a pooled transaction."""
        return self._fees.get(txid)

    def fee_rate_of(self, txid: bytes) -> float:
        size = self._sizes.get(txid) or 1
        fee = self._fees.get(txid) or 0
        return fee / max(1, size)

    def _evict_for(self, incoming_size: int) -> bool:
        """Drop lowest-fee txs (and expired ones) until `incoming_size`
        fits.  Returns True when enough room was freed."""
        now = time.time()
        # expiry sweep first
        expired = [t for t, ts in self._added_at.items()
                   if now - ts > C.MEMPOOL_EVICT_AGE]
        for t in expired:
            self._drop_txid(t)
        need = self.total_size() + incoming_size - C.MAX_MEMPOOL_SIZE
        if need <= 0:
            return True
        ranked = sorted(self.txs, key=lambda t: self.fee_rate_of(t))
        for t in ranked:
            if need <= 0:
                break
            need -= self._sizes.get(t, 0)
            self._drop_txid(t)
        return need <= 0

    def _drop_txid(self, txid: bytes):
        self.txs.pop(txid, None)
        self._fees.pop(txid, None)
        self._sizes.pop(txid, None)
        self._added_at.pop(txid, None)
        self._rebuild_overlay()

    def remove_tx(self, txid: bytes):
        with self.lock:
            if txid in self.txs:
                self._drop_txid(txid)

    def _rebuild_overlay(self):
        self._overlay = {}
        self._overlay_removed = set()
        self._addr_pending_nonce = {}
        for tx in self.txs.values():
            for inp in tx.inputs:
                op = (inp.prev_txid, inp.prev_index)
                self._overlay.pop(op, None)
                self._overlay_removed.add(op)
            from qeuph.crypto.address import pk_to_hash
            for inp in tx.inputs:
                self._addr_pending_nonce[pk_to_hash(inp.pubkey)] = inp.txnonce
            txid = tx.txid()
            for i, out in enumerate(tx.outputs):
                self._overlay[(txid, i)] = UTXO(out.addr_hash, out.value, False, 0)

    # ------------------------------------------------------------------
    def on_new_block(self, block):
        """Drop transactions included in / invalidated by a newly connected
        block."""
        with self.lock:
            included = {tx.txid() for tx in block.transactions}
            drop = []
            view = _StateView(lambda t, i: self.state.get_utxo(t, i),
                              lambda a: self.state.nonce_of(a))
            for txid, tx in self.txs.items():
                if txid in included:
                    drop.append(txid)
                    continue
                # still valid against new state?
                try:
                    validate_tx(tx, view, height=block.height,
                                fee_rate=self.fee_rate)
                except TxValidationError:
                    drop.append(txid)
            for txid in drop:
                self.txs.pop(txid, None)
                self._fees.pop(txid, None)
                self._sizes.pop(txid, None)
                self._added_at.pop(txid, None)
            self._rebuild_overlay()

    def readd_many(self, txs: List[Transaction]):
        """After a reorg, try to re-admit transactions from disconnected
        blocks (silently skipping ones that no longer validate)."""
        for tx in txs:
            try:
                self.add_tx(tx)
            except TxValidationError:
                pass

    # ------------------------------------------------------------------
    def best_transactions(self, max_bytes: int) -> List[Transaction]:
        """Highest-fee-per-byte transactions that fit a block template.

        Candidates are validated against the confirmed state plus a local
        overlay built from the transactions already selected into the
        template, so chained spends (nonce n then n+1) are ordered
        correctly and outpoint conflicts are skipped.
        """
        with self.lock:
            ranked = sorted(self.txs.values(),
                            key=lambda t: -self.fee_rate_of(t.txid()))
            chosen: List[Transaction] = []
            local_utxos: Dict[Tuple[bytes, int], UTXO] = {}
            local_removed = set()
            local_nonce: Dict[bytes, int] = {}
            height = self._height_fn()
            mtp = self._mtp_fn()

            def lookup(t, i):
                op = (t, i)
                if op in local_removed:
                    return None
                if op in local_utxos:
                    return local_utxos[op]
                return self.state.get_utxo(t, i)

            def nonce_of(a):
                return local_nonce.get(a, self.state.nonce_of(a))

            view = _StateView(lookup, nonce_of)

            used = 0
            from qeuph.crypto.address import pk_to_hash
            for tx in ranked:
                size = self._sizes.get(tx.txid()) or tx.size()
                if used + size > max_bytes:
                    continue
                try:
                    validate_tx(tx, view, height=height, mtp=mtp)
                except TxValidationError:
                    continue
                chosen.append(tx)
                used += size
                for inp in tx.inputs:
                    local_removed.add((inp.prev_txid, inp.prev_index))
                    local_nonce[pk_to_hash(inp.pubkey)] = inp.txnonce
                txid = tx.txid()
                for i, out in enumerate(tx.outputs):
                    local_utxos[(txid, i)] = UTXO(out.addr_hash, out.value,
                                                  False, height)
            return chosen

    def total_size(self) -> int:
        return sum(self._sizes.get(t) or 0 for t in self.txs)

    def __len__(self):
        return len(self.txs)

    def get_tx(self, txid: bytes) -> Optional[Transaction]:
        return self.txs.get(txid)

    def all_txs(self) -> List[Transaction]:
        return list(self.txs.values())

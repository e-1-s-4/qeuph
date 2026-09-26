"""
Mempool: pending transactions awaiting block inclusion.

Ported from QRL's TransactionPool (qrl/core/TransactionPool.py) to the
UTXO + txnonce model.  Transactions are accepted only when they validate
against the confirmed chain state overlaid with already-pending spends,
which naturally enforces per-address nonce ordering inside the pool.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

from qeuph import constants as C
from qeuph.core.state import UTXO
from qeuph.core.tx import Transaction
from qeuph.core.validation import TxValidationError, validate_tx


class Mempool:
    def __init__(self, state, fee_rate: int = C.MIN_RELAY_FEE_RATE,
                 height_fn=None):
        self.state = state
        self.fee_rate = fee_rate
        self._height_fn = height_fn or (lambda: 0)
        self.lock = threading.RLock()
        self.txs: Dict[bytes, Transaction] = {}
        # overlay: outpoint -> UTXO as it would be after pending txs
        self._overlay: Dict[Tuple[bytes, int], UTXO] = {}
        self._template_consumed = []
        self._overlay_removed = set()
        # per-address pending nonce/utxo picture
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

    # ------------------------------------------------------------------
    def add_tx(self, tx: Transaction) -> int:
        """Validate and admit a transaction.  Returns its fee."""
        if tx.is_coinbase:
            raise TxValidationError("coinbase cannot enter mempool")
        with self.lock:
            txid = tx.txid()
            if txid in self.txs:
                raise TxValidationError("transaction already in mempool")
            if self.total_size() + tx.size() > C.MAX_MEMPOOL_SIZE:
                raise TxValidationError("mempool full")

            # validate against state + overlay with mempool-aware nonce
            class _NS:
                pass
            ns = _NS()
            ns.get_utxo = self._lookup
            ns.nonce_of = self._nonce_of
            fee = validate_tx(tx, ns, height=self._height_fn(),
                              fee_rate=self.fee_rate)

            # apply to overlay
            for inp in tx.inputs:
                op = (inp.prev_txid, inp.prev_index)
                self._overlay.pop(op, None)
                self._overlay_removed.add(op)
            from qeuph.crypto.address import pk_to_hash
            for inp in tx.inputs:
                self._addr_pending_nonce[pk_to_hash(inp.pubkey)] = inp.txnonce
            txid_ = tx.txid()
            for i, out in enumerate(tx.outputs):
                self._overlay[(txid_, i)] = UTXO(out.addr_hash, out.value, False, 0)
            self.txs[txid] = tx
            return fee

    # ------------------------------------------------------------------
    def remove_tx(self, txid: bytes):
        with self.lock:
            tx = self.txs.pop(txid, None)
            if tx is None:
                return
            self._rebuild_overlay()

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
        """Drop transactions included in / invalidated by a newly connected block."""
        with self.lock:
            included = {tx.txid() for tx in block.transactions}
            drop = []
            for txid, tx in self.txs.items():
                if txid in included:
                    drop.append(txid)
                    continue
                # still valid against new state?
                try:
                    class _NS:
                        pass
                    ns = _NS()
                    ns.get_utxo = lambda t, i: self.state.get_utxo(t, i)
                    ns.nonce_of = lambda a: self.state.nonce_of(a)
                    validate_tx(tx, ns, height=block.height, fee_rate=self.fee_rate)
                except TxValidationError:
                    drop.append(txid)
            for txid in drop:
                self.txs.pop(txid, None)
            self._rebuild_overlay()

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
                            key=lambda t: -(self._fee(t) / max(1, t.size())))
            chosen: List[Transaction] = []
            local_utxos: Dict[Tuple[bytes, int], UTXO] = {}
            local_removed = set()
            local_nonce: Dict[bytes, int] = {}
            height = self._height_fn()

            class _NS:
                pass

            def lookup(t, i):
                op = (t, i)
                if op in local_removed:
                    return None
                if op in local_utxos:
                    return local_utxos[op]
                return self.state.get_utxo(t, i)

            def nonce_of(a):
                return local_nonce.get(a, self.state.nonce_of(a))

            ns = _NS()
            ns.get_utxo = lookup
            ns.nonce_of = nonce_of

            used = 0
            from qeuph.crypto.address import pk_to_hash
            for tx in ranked:
                if used + tx.size() > max_bytes:
                    continue
                try:
                    validate_tx(tx, ns, height=height)
                except TxValidationError:
                    continue
                chosen.append(tx)
                used += tx.size()
                for inp in tx.inputs:
                    local_removed.add((inp.prev_txid, inp.prev_index))
                    local_nonce[pk_to_hash(inp.pubkey)] = inp.txnonce
                txid = tx.txid()
                for i, out in enumerate(tx.outputs):
                    local_utxos[(txid, i)] = UTXO(out.addr_hash, out.value, False, height)
            return chosen

    def _fee(self, tx) -> int:
        total_in = 0
        for inp in tx.inputs:
            u = self._lookup(inp.prev_txid, inp.prev_index)
            if u is not None:
                total_in += u.value
        return total_in - tx.total_out

    def total_size(self) -> int:
        return sum(tx.size() for tx in self.txs.values())

    def __len__(self):
        return len(self.txs)

    def get_tx(self, txid: bytes) -> Optional[Transaction]:
        return self.txs.get(txid)

    def all_txs(self) -> List[Transaction]:
        return list(self.txs.values())

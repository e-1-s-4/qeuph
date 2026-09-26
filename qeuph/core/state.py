"""
Chain state: UTXO set + per-address txnonce counters.

Qeuph tracks both:
  * utxos:  {(txid, index) -> (addr_hash, value, is_coinbase, cb_height)}
  * nonces: {addr_hash -> last used txnonce}

The txnonce map implements the whitepaper's replay protection: every
non-coinbase transaction must carry, on each input, the next sequential
nonce for that input's address.  Addresses that never sent a transaction
have an implicit nonce of 0, so their first spend uses nonce 1.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

OutPoint = Tuple[bytes, int]          # (txid 64B, index)


class UTXO:
    __slots__ = ("addr_hash", "value", "is_coinbase", "cb_height")

    def __init__(self, addr_hash: bytes, value: int,
                 is_coinbase: bool = False, cb_height: int = 0):
        self.addr_hash = addr_hash
        self.value = value
        self.is_coinbase = is_coinbase
        self.cb_height = cb_height


class ChainState:
    """In-memory chain state; the SQLite store mirrors it for restarts."""

    def __init__(self):
        self.utxos: Dict[OutPoint, UTXO] = {}
        self.nonces: Dict[bytes, int] = {}

    # ------------------------------------------------------------------
    def copy(self) -> "ChainState":
        st = ChainState()
        st.utxos = dict(self.utxos)
        st.nonces = dict(self.nonces)
        return st

    # ------------------------------------------------------------------
    def get_utxo(self, txid: bytes, index: int) -> Optional[UTXO]:
        return self.utxos.get((txid, index))

    def nonce_of(self, addr_hash: bytes) -> int:
        return self.nonces.get(addr_hash, 0)

    # ------------------------------------------------------------------
    def apply_transaction(self, tx, height: int) -> None:
        """Apply a validated transaction (mutates state)."""
        from qeuph.core.tx import Transaction
        txid = tx.txid()
        if tx.is_coinbase:
            for i, out in enumerate(tx.outputs):
                self.utxos[(txid, i)] = UTXO(out.addr_hash, out.value,
                                             True, height)
            return
        # consume inputs
        for inp in tx.inputs:
            self.utxos.pop((inp.prev_txid, inp.prev_index), None)
        # bump nonces (per distinct address, idempotent within one tx)
        from qeuph.crypto.address import pk_to_hash
        for inp in tx.inputs:
            self.nonces[pk_to_hash(inp.pubkey)] = inp.txnonce
        # create outputs
        for i, out in enumerate(tx.outputs):
            self.utxos[(txid, i)] = UTXO(out.addr_hash, out.value, False, height)

    def apply_block(self, block) -> None:
        for tx in block.transactions:
            self.apply_transaction(tx, block.height)

    # ------------------------------------------------------------------
    def balance(self, addr_hash: bytes, height: Optional[int] = None,
                matured_only: bool = False) -> int:
        """Total value locked to addr_hash.  With matured_only=True coinbase
        outputs younger than COINBASE_MATURITY blocks (relative to `height`)
        are excluded."""
        from qeuph import constants as C
        total = 0
        for (_txid, _idx), u in self.utxos.items():
            if u.addr_hash != addr_hash:
                continue
            if matured_only and u.is_coinbase and height is not None and \
                    (height - u.cb_height) < C.COINBASE_MATURITY:
                continue
            total += u.value
        return total

    def utxos_for(self, addr_hash: bytes, height: Optional[int] = None,
                  matured_only: bool = False) -> list:
        from qeuph import constants as C
        out = []
        for (txid, idx), u in sorted(self.utxos.items()):
            if u.addr_hash != addr_hash:
                continue
            if matured_only and u.is_coinbase and height is not None and \
                    (height - u.cb_height) < C.COINBASE_MATURITY:
                continue
            out.append((txid, idx, u))
        return out

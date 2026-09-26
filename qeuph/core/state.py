"""
Chain state: UTXO set + per-address txnonce counters.

Qeuph tracks both:
  * utxos:  {(txid, index) -> (addr_hash, value, is_coinbase, cb_height)}
  * nonces: {addr_hash -> last used txnonce}

The txnonce map implements the whitepaper's replay protection: every
non-coinbase transaction must carry, on each input, the next sequential
nonce for that input's address.  Addresses that never sent a transaction
have an implicit nonce of 0, so their first spend uses nonce 1.

An address index (addr_hash -> set of outpoints) keeps balance and UTXO
queries proportional to the address's own outputs instead of the entire
UTXO set, and block application/removal uses an undo log so validation
never needs to copy the whole state.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set, Tuple

OutPoint = Tuple[bytes, int]          # (txid 64B, index)


class UTXO:
    __slots__ = ("addr_hash", "value", "is_coinbase", "cb_height")

    def __init__(self, addr_hash: bytes, value: int,
                 is_coinbase: bool = False, cb_height: int = 0):
        self.addr_hash = addr_hash
        self.value = value
        self.is_coinbase = is_coinbase
        self.cb_height = cb_height

    def __repr__(self):  # pragma: no cover
        return (f"UTXO({self.addr_hash.hex()[:12]}.., {self.value}, "
                f"cb={self.is_coinbase}, h={self.cb_height})")


class UndoBlock:
    """Records the exact mutations a block made so it can be rolled back.

    Fields:
      removed:   [outpoint] outputs consumed by the block (spent inputs)
      removed_entries: [(outpoint, UTXO)] so rollback can restore them
      added:     [outpoint] outputs created by the block
      nonces:    [(addr_hash, previous_nonce)] nonce overwrites
    """

    __slots__ = ("removed_entries", "added", "nonces")

    def __init__(self):
        self.removed_entries: List[Tuple[OutPoint, UTXO]] = []
        self.added: List[OutPoint] = []
        self.nonces: List[Tuple[bytes, int]] = []


class ChainState:
    """In-memory chain state; the SQLite store mirrors it for restarts."""

    def __init__(self):
        self.utxos: Dict[OutPoint, UTXO] = {}
        self.nonces: Dict[bytes, int] = {}
        # address index: addr_hash -> set of outpoints owned by it
        self._by_addr: Dict[bytes, Set[OutPoint]] = {}

    # ------------------------------------------------------------------
    def copy(self) -> "ChainState":
        """Deep-enough copy (kept for tests and external tooling)."""
        st = ChainState()
        st.utxos = dict(self.utxos)
        st.nonces = dict(self.nonces)
        for a, ops in self._by_addr.items():
            st._by_addr[a] = set(ops)
        return st

    # ------------------------------------------------------------------
    def get_utxo(self, txid: bytes, index: int) -> Optional[UTXO]:
        return self.utxos.get((txid, index))

    def nonce_of(self, addr_hash: bytes) -> int:
        return self.nonces.get(addr_hash, 0)

    # ------------------------------------------------------------------
    # index maintenance
    # ------------------------------------------------------------------
    def _index_add(self, op: OutPoint, u: UTXO):
        s = self._by_addr.get(u.addr_hash)
        if s is None:
            s = set()
            self._by_addr[u.addr_hash] = s
        s.add(op)

    def _index_remove(self, op: OutPoint, u: UTXO):
        s = self._by_addr.get(u.addr_hash)
        if s is not None:
            s.discard(op)
            if not s:
                del self._by_addr[u.addr_hash]

    # ------------------------------------------------------------------
    # transaction / block application with undo
    # ------------------------------------------------------------------
    def apply_transaction(self, tx, height: int,
                          undo: Optional[UndoBlock] = None) -> None:
        """Apply a validated transaction (mutates state, records undo)."""
        txid = tx.cached_txid()
        if tx.is_coinbase:
            for i, out in enumerate(tx.outputs):
                op = (txid, i)
                u = UTXO(out.addr_hash, out.value, True, height)
                self.utxos[op] = u
                self._index_add(op, u)
                if undo is not None:
                    undo.added.append(op)
            return
        # consume inputs
        for inp in tx.inputs:
            op = (inp.prev_txid, inp.prev_index)
            u = self.utxos.pop(op, None)
            if u is not None:
                self._index_remove(op, u)
                if undo is not None:
                    undo.removed_entries.append((op, u))
        # bump nonces (per distinct address, idempotent within one tx)
        from qeuph.crypto.address import pk_to_hash
        for inp in tx.inputs:
            ah = pk_to_hash(inp.pubkey)
            prev = self.nonces.get(ah)
            self.nonces[ah] = inp.txnonce
            if undo is not None and prev != inp.txnonce:
                undo.nonces.append((ah, prev if prev is not None else 0))
        # create outputs
        for i, out in enumerate(tx.outputs):
            op = (txid, i)
            u = UTXO(out.addr_hash, out.value, False, height)
            self.utxos[op] = u
            self._index_add(op, u)
            if undo is not None:
                undo.added.append(op)

    def apply_block(self, block, undo: Optional[UndoBlock] = None) -> None:
        for tx in block.transactions:
            self.apply_transaction(tx, block.height, undo)

    def undo_block(self, undo: UndoBlock) -> None:
        """Roll back a previously applied block."""
        # remove created outputs (reverse order)
        for op in reversed(undo.added):
            u = self.utxos.pop(op, None)
            if u is not None:
                self._index_remove(op, u)
        # restore nonce overwrites (reverse order restores the originals)
        for ah, prev in reversed(undo.nonces):
            if prev:
                self.nonces[ah] = prev
            else:
                self.nonces.pop(ah, None)
        # restore consumed inputs
        for op, u in undo.removed_entries:
            self.utxos[op] = u
            self._index_add(op, u)

    # ------------------------------------------------------------------
    # queries (address-index backed)
    # ------------------------------------------------------------------
    def balance(self, addr_hash: bytes, height: Optional[int] = None,
                matured_only: bool = False) -> int:
        """Total value locked to addr_hash.  With matured_only=True coinbase
        outputs younger than COINBASE_MATURITY blocks (relative to `height`)
        are excluded."""
        from qeuph import constants as C
        total = 0
        for op in self._by_addr.get(addr_hash, ()):
            u = self.utxos.get(op)
            if u is None:
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
        for op in sorted(self._by_addr.get(addr_hash, ())):
            u = self.utxos.get(op)
            if u is None:
                continue
            if matured_only and u.is_coinbase and height is not None and \
                    (height - u.cb_height) < C.COINBASE_MATURITY:
                continue
            out.append((op[0], op[1], u))
        return out

    def utxo_count(self) -> int:
        return len(self.utxos)

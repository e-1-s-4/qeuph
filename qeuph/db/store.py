"""
SQLite-backed persistence for blocks, chain state and metadata.

QRL used RocksDB via plyvel; Qeuph ships with SQLite (stdlib) so the full
node suite has zero mandatory native dependencies.  The schema:

    meta     (key, value)                  -- tip, network, schema version
    blocks   (hash, height, raw, work)     -- every stored block
    utxos    (txid, idx, addr, value, is_cb, cb_height)
    nonces   (addr, nonce)
    tx_index (txid, height, hash)          -- txid -> containing block
    main_chain (height, hash)              -- canonical chain index

Blocks are stored with 64-byte little-endian cumulative work (enough for
the full 512-bit work space), so any stored side chain can be compared
against the tip by cumulative work directly.

The UTXO set is maintained INCREMENTALLY per block (apply/undo deltas)
instead of rewriting the full set; `save_state` remains available for
explicit snapshots and is used at genesis init and load.

The connection is shared across threads (event loop, RPC handlers and the
miner thread) behind a re-entrant lock; WAL journaling keeps readers and
the writer out of each other's way.
"""
from __future__ import annotations

import sqlite3
import struct
import threading
from typing import List, Optional, Tuple

from qeuph.core.block import Block
from qeuph.core.state import ChainState, UTXO

SCHEMA_VERSION = 2

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB
);
CREATE TABLE IF NOT EXISTS blocks (
    hash BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    parent BLOB NOT NULL,
    raw BLOB NOT NULL,
    work BLOB
);
CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height);
CREATE INDEX IF NOT EXISTS idx_blocks_parent ON blocks(parent);
CREATE INDEX IF NOT EXISTS idx_blocks_work ON blocks(work DESC);
CREATE TABLE IF NOT EXISTS utxos (
    txid BLOB NOT NULL,
    idx INTEGER NOT NULL,
    addr BLOB NOT NULL,
    value INTEGER NOT NULL,
    is_cb INTEGER NOT NULL,
    cb_height INTEGER NOT NULL,
    PRIMARY KEY (txid, idx)
);
CREATE INDEX IF NOT EXISTS idx_utxos_addr ON utxos(addr);
CREATE TABLE IF NOT EXISTS nonces (
    addr BLOB PRIMARY KEY,
    nonce INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tx_index (
    txid BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    hash BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tx_index_height ON tx_index(height);
CREATE TABLE IF NOT EXISTS main_chain (
    height INTEGER PRIMARY KEY,
    hash BLOB NOT NULL
);
"""

WORK_BYTES = 64


def _pack_work(work: int) -> bytes:
    """64-byte BIG-endian encoding so SQL BLOB comparison (memcmp) matches
    numeric comparison, enabling the work index to order correctly."""
    if work < 0:
        raise ValueError("negative work")
    return work.to_bytes(WORK_BYTES, "big")


def _unpack_work(blob: bytes) -> int:
    return int.from_bytes(blob[:WORK_BYTES], "big")


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA foreign_keys=OFF")
        with self._lock:
            self._db.executescript(SCHEMA)
            # schema versioning: incompatible stores start fresh
            v = self.get_meta("schema")
            if v is None:
                self.set_meta("schema", struct.pack("<I", SCHEMA_VERSION))
            elif int.from_bytes(v, "little") != SCHEMA_VERSION:
                self._wipe()
                self.set_meta("schema", struct.pack("<I", SCHEMA_VERSION))
            self._db.commit()

    def _wipe(self):
        """Drop all tables (incompatible schema found) and recreate."""
        for t in ("meta", "blocks", "utxos", "nonces", "tx_index", "main_chain"):
            self._db.execute(f"DROP TABLE IF EXISTS {t}")
        self._db.executescript(SCHEMA)
        self._db.commit()

    # ------------------------------------------------------------------
    def close(self):
        with self._lock:
            try:
                self._db.commit()
            except Exception:
                pass
            self._db.close()

    # ------------------------------------------------------------------
    # meta
    # ------------------------------------------------------------------
    def get_meta(self, key: str) -> Optional[bytes]:
        with self._lock:
            row = self._db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            return None if row is None else row[0]

    def set_meta(self, key: str, value: bytes):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (key, value))
            self._db.commit()

    # ------------------------------------------------------------------
    # blocks
    # ------------------------------------------------------------------
    def put_block(self, block: Block, work: Optional[int]):
        """Store a block with its cumulative work (None = unknown/orphan)."""
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO blocks VALUES (?, ?, ?, ?, ?)",
                (block.hash, block.height, block.header.prev_hash,
                 block.serialize(),
                 None if work is None else _pack_work(work)))
            for tx in block.transactions:
                self._db.execute("INSERT OR REPLACE INTO tx_index VALUES (?, ?, ?)",
                                 (tx.txid(), block.height, block.hash))
            self._db.commit()

    def set_block_work(self, block_hash: bytes, work: int):
        with self._lock:
            self._db.execute("UPDATE blocks SET work=? WHERE hash=?",
                             (_pack_work(work), block_hash))
            self._db.commit()

    def remove_block(self, block_hash: bytes):
        """Delete a block and its tx index entries (invalid side chains)."""
        with self._lock:
            row = self._db.execute("SELECT height, raw FROM blocks WHERE hash=?",
                                   (block_hash,)).fetchone()
            if row is None:
                return
            from qeuph.core.block import Block
            blk = Block.deserialize(row[1])
            for tx in blk.transactions:
                self._db.execute("DELETE FROM tx_index WHERE txid=?", (tx.txid(),))
            self._db.execute("DELETE FROM blocks WHERE hash=?", (block_hash,))
            self._db.commit()

    def get_block_by_hash(self, block_hash: bytes) -> Optional[Block]:
        with self._lock:
            row = self._db.execute("SELECT raw FROM blocks WHERE hash=?",
                                   (block_hash,)).fetchone()
            return None if row is None else Block.deserialize(row[0])

    def block_raw(self, block_hash: bytes) -> Optional[bytes]:
        with self._lock:
            row = self._db.execute("SELECT raw FROM blocks WHERE hash=?",
                                   (block_hash,)).fetchone()
            return None if row is None else row[0]

    def set_main_block(self, height: int, block_hash: bytes):
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO main_chain VALUES (?, ?)",
                             (height, block_hash))
            self._db.commit()

    def truncate_main_chain(self, from_height: int):
        with self._lock:
            self._db.execute("DELETE FROM main_chain WHERE height >= ?", (from_height,))
            self._db.commit()

    def get_main_hash_at_height(self, height: int) -> Optional[bytes]:
        with self._lock:
            row = self._db.execute("SELECT hash FROM main_chain WHERE height=?",
                                   (height,)).fetchone()
            return None if row is None else row[0]

    def get_block_by_height(self, height: int) -> Optional[Block]:
        with self._lock:
            # Query canonical block on main chain first
            row = self._db.execute(
                "SELECT b.raw FROM main_chain m JOIN blocks b ON m.hash = b.hash "
                "WHERE m.height=?", (height,)).fetchone()
            if row is not None:
                return Block.deserialize(row[0])
            # Fallback for unindexed or single block
            row = self._db.execute(
                "SELECT raw FROM blocks WHERE height=? ORDER BY hash LIMIT 1",
                (height,)).fetchone()
            return None if row is None else Block.deserialize(row[0])

    def get_work(self, block_hash: bytes) -> Optional[int]:
        """Cumulative work of a stored block; None when unknown/orphan."""
        with self._lock:
            row = self._db.execute("SELECT work FROM blocks WHERE hash=?",
                                   (block_hash,)).fetchone()
            if row is None or row[0] is None:
                return None
            return _unpack_work(row[0])

    def block_exists(self, block_hash: bytes) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM blocks WHERE hash=?",
                                    (block_hash,)).fetchone() is not None

    def get_block_hashes_by_height(self, height: int) -> List[bytes]:
        with self._lock:
            return [r[0] for r in self._db.execute(
                "SELECT hash FROM blocks WHERE height=?", (height,)).fetchall()]

    def best_stored_chain_head(self, min_work: int) -> Optional[Tuple[bytes, int]]:
        """The stored block with the highest cumulative work, when it beats
        `min_work`.  Any block with known cumulative work competes for the
        main chain (most-cumulative-work fork choice, whitepaper 4.2)."""
        with self._lock:
            row = self._db.execute(
                "SELECT hash, work FROM blocks WHERE work IS NOT NULL "
                "ORDER BY work DESC LIMIT 1").fetchone()
            if row is None or row[0] is None:
                return None
            w = _unpack_work(row[0])
            if w <= min_work:
                return None
            return row[0], w

    def children_of(self, block_hash: bytes) -> List[bytes]:
        with self._lock:
            return [r[0] for r in self._db.execute(
                "SELECT hash FROM blocks WHERE parent=?", (block_hash,)).fetchall()]

    # ------------------------------------------------------------------
    # transactions
    # ------------------------------------------------------------------
    def get_tx_block(self, txid: bytes) -> Optional[Tuple[int, bytes]]:
        with self._lock:
            row = self._db.execute("SELECT height, hash FROM tx_index WHERE txid=?",
                                   (txid,)).fetchone()
            return None if row is None else (row[0], row[1])

    def get_transactions_at_height(self, height: int, block_hash: bytes) -> List:
        blk = self.get_block_by_hash(block_hash)
        return [] if blk is None else blk.transactions

    # ------------------------------------------------------------------
    # chain state (incremental deltas + snapshots)
    # ------------------------------------------------------------------
    def apply_block_delta(self, block, spent: List[Tuple[bytes, int]],
                          created: List[Tuple[Tuple[bytes, int], UTXO]],
                          nonces: List[Tuple[bytes, int]],
                          tip_hash: bytes, tip_height: int):
        """Incrementally apply a connected block to the persisted state."""
        with self._lock:
            cur = self._db
            for (txid, idx) in spent:
                cur.execute("DELETE FROM utxos WHERE txid=? AND idx=?", (txid, idx))
            cur.executemany(
                "INSERT OR REPLACE INTO utxos VALUES (?, ?, ?, ?, ?, ?)",
                [(txid, idx, u.addr_hash, u.value,
                  1 if u.is_coinbase else 0, u.cb_height)
                 for (txid, idx), u in created])
            cur.executemany("INSERT OR REPLACE INTO nonces VALUES (?, ?)", nonces)
            self.set_meta("tip", tip_hash)
            self.set_meta("tip_height", struct.pack("<Q", tip_height))
            cur.commit()

    def undo_block_delta(self, spent: List[Tuple[Tuple[bytes, int], UTXO]],
                         created: List[Tuple[bytes, int]],
                         nonces: List[Tuple[bytes, int]],
                         tip_hash: bytes, tip_height: int):
        """Incrementally roll back a disconnected block."""
        with self._lock:
            cur = self._db
            for (txid, idx) in created:
                cur.execute("DELETE FROM utxos WHERE txid=? AND idx=?", (txid, idx))
            cur.executemany(
                "INSERT OR REPLACE INTO utxos VALUES (?, ?, ?, ?, ?, ?)",
                [(txid, idx, u.addr_hash, u.value,
                  1 if u.is_coinbase else 0, u.cb_height)
                 for (txid, idx), u in spent])
            # restore previous nonces (0 => remove row)
            for addr, prev in nonces:
                if prev:
                    cur.execute("INSERT OR REPLACE INTO nonces VALUES (?, ?)",
                                (addr, prev))
                else:
                    cur.execute("DELETE FROM nonces WHERE addr=?", (addr,))
            self.set_meta("tip", tip_hash)
            self.set_meta("tip_height", struct.pack("<Q", tip_height))
            cur.commit()

    def save_state(self, state: ChainState, tip_hash: bytes, tip_height: int):
        """Full state snapshot (genesis init / explicit checkpoint)."""
        with self._lock:
            cur = self._db
            cur.execute("DELETE FROM utxos")
            cur.execute("DELETE FROM nonces")
            cur.executemany(
                "INSERT INTO utxos VALUES (?, ?, ?, ?, ?, ?)",
                [(txid, idx, u.addr_hash, u.value,
                  1 if u.is_coinbase else 0, u.cb_height)
                 for (txid, idx), u in state.utxos.items()])
            cur.executemany(
                "INSERT OR REPLACE INTO nonces VALUES (?, ?)",
                list(state.nonces.items()))
            self.set_meta("tip", tip_hash)
            self.set_meta("tip_height", struct.pack("<Q", tip_height))
            cur.commit()

    def load_state(self) -> Tuple[Optional[ChainState], Optional[bytes], Optional[int]]:
        with self._lock:
            tip = self.get_meta("tip")
            if tip is None:
                return None, None, None
            state = ChainState()
            for txid, idx, addr, value, is_cb, cb_h in self._db.execute(
                    "SELECT txid, idx, addr, value, is_cb, cb_height FROM utxos"):
                state.utxos[(txid, idx)] = UTXO(addr, value, bool(is_cb), cb_h)
            for addr, nonce in self._db.execute("SELECT addr, nonce FROM nonces"):
                state.nonces[addr] = nonce
            # rebuild the address index
            for op, u in state.utxos.items():
                state._index_add(op, u)
            th = self.get_meta("tip_height")
            tip_height = struct.unpack("<Q", th)[0] if th else 0
            return state, tip, tip_height

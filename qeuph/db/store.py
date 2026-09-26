"""
SQLite-backed persistence for blocks, chain state and metadata.

QRL used RocksDB via plyvel; Qeuph ships with SQLite (stdlib) so the full
node suite has zero mandatory native dependencies.  The schema:

    meta     (key, value)                  -- tip, network, versions
    blocks   (hash, height, raw, work)     -- every stored block
    utxos    (txid, idx, addr, value, is_cb, cb_height)
    nonces   (addr, nonce)
    tx_index (txid, height, hash)          -- txid -> containing block

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

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB
);
CREATE TABLE IF NOT EXISTS blocks (
    hash BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    raw BLOB NOT NULL,
    work BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height);
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
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA)
        self._db.commit()

    # ------------------------------------------------------------------
    def close(self):
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
    def put_block(self, block: Block, work: int):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO blocks VALUES (?, ?, ?, ?)",
                (block.hash, block.height, block.serialize(),
                 work.to_bytes(32, "little")))
            for tx in block.transactions:
                self._db.execute("INSERT OR REPLACE INTO tx_index VALUES (?, ?, ?)",
                                 (tx.txid(), block.height, block.hash))
            self._db.commit()

    def get_block_by_hash(self, block_hash: bytes) -> Optional[Block]:
        with self._lock:
            row = self._db.execute("SELECT raw FROM blocks WHERE hash=?",
                                   (block_hash,)).fetchone()
            return None if row is None else Block.deserialize(row[0])

    def get_block_by_height(self, height: int) -> Optional[Block]:
        with self._lock:
            row = self._db.execute("SELECT raw FROM blocks WHERE height=? ORDER BY hash LIMIT 1",
                                   (height,)).fetchone()
            return None if row is None else Block.deserialize(row[0])

    def get_work(self, block_hash: bytes) -> Optional[int]:
        with self._lock:
            row = self._db.execute("SELECT work FROM blocks WHERE hash=?",
                                   (block_hash,)).fetchone()
            return None if row is None else int.from_bytes(row[0], "little")

    def block_exists(self, block_hash: bytes) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM blocks WHERE hash=?",
                                    (block_hash,)).fetchone() is not None

    def get_block_hashes_by_height(self, height: int) -> List[bytes]:
        with self._lock:
            return [r[0] for r in self._db.execute(
                "SELECT hash FROM blocks WHERE height=?", (height,)).fetchall()]

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
    # chain state snapshot
    # ------------------------------------------------------------------
    def save_state(self, state: ChainState, tip_hash: bytes, tip_height: int):
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
            tip_height = struct.unpack("<Q", self.get_meta("tip_height"))[0]
            return state, tip, tip_height

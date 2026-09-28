"""
SQLite-backed persistence for blocks, chain state and metadata.

QRL used RocksDB via plyvel; Qeuph ships with SQLite (stdlib) so the full
node suite has zero mandatory native dependencies.  The schema:

    meta      (key, value)                 -- tip, network, schema version
    blocks    (hash, height, parent, raw, work, main)
    utxos     (txid, idx, addr, value, is_cb, cb_height)
    nonces    (addr, nonce)
    tx_index  (txid, height, hash)         -- txid -> containing block
    main_chain(height, hash)               -- canonical chain index
    bans      (addr, until, score, reason)

Blocks are stored with 64-byte big-endian cumulative work (enough for the
full 512-bit work space) so any stored side chain can be compared against
the tip by cumulative work directly, and SQLite's memcmp-based BLOB ordering
matches numeric ordering so the work index sorts correctly.

Crash safety: every state transition (connecting a block, reorganising,
initialising genesis) is written inside a SINGLE SQLite transaction.  The
`meta.tip` / `meta.tip_height` keys are advanced last, inside that same
transaction, so a crash at any point leaves the store on a block boundary:
either the previous tip (state and index both at the old tip) or the new one.
`verify_main_chain` re-checks that invariant on load.

The UTXO set is maintained INCREMENTALLY per block (apply deltas) instead of
rewriting the full set; `save_state` remains available for explicit snapshots
and is used at genesis init, after a reorganisation, and on demand.

The connection is shared across threads (event loop, RPC handlers and the
miner thread) behind a re-entrant lock; WAL journaling keeps readers and
the writer out of each other's way.
"""
from __future__ import annotations

import contextlib
import sqlite3
import struct
import threading
import time
from typing import List, Optional, Tuple

from qeuph.core.block import Block
from qeuph.core.state import ChainState, UTXO

SCHEMA_VERSION = 3

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB
)""",
    """CREATE TABLE IF NOT EXISTS blocks (
    hash BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    parent BLOB NOT NULL,
    raw BLOB NOT NULL,
    work BLOB
)""",
    "CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height)",
    "CREATE INDEX IF NOT EXISTS idx_blocks_parent ON blocks(parent)",
    "CREATE INDEX IF NOT EXISTS idx_blocks_work ON blocks(work DESC)",
    """CREATE TABLE IF NOT EXISTS utxos (
    txid BLOB NOT NULL,
    idx INTEGER NOT NULL,
    addr BLOB NOT NULL,
    value INTEGER NOT NULL,
    is_cb INTEGER NOT NULL,
    cb_height INTEGER NOT NULL,
    PRIMARY KEY (txid, idx)
)""",
    "CREATE INDEX IF NOT EXISTS idx_utxos_addr ON utxos(addr)",
    """CREATE TABLE IF NOT EXISTS nonces (
    addr BLOB PRIMARY KEY,
    nonce INTEGER NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS tx_index (
    txid BLOB PRIMARY KEY,
    height INTEGER NOT NULL,
    hash BLOB NOT NULL
)""",
    "CREATE INDEX IF NOT EXISTS idx_tx_index_height ON tx_index(height)",
    """CREATE TABLE IF NOT EXISTS main_chain (
    height INTEGER PRIMARY KEY,
    hash BLOB NOT NULL
)""",
    """CREATE TABLE IF NOT EXISTS bans (
    addr TEXT PRIMARY KEY,
    until REAL NOT NULL,
    score INTEGER NOT NULL DEFAULT 0,
    reason TEXT
)""",
]

WORK_BYTES = 64

_TABLES = ("meta", "blocks", "utxos", "nonces", "tx_index", "main_chain", "bans")


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
        self._local_depth = threading.local()
        # isolation_level=None -> autocommit; every state transition opens its
        # own explicit BEGIN IMMEDIATE and commit() controls COMMIT, which is
        # what makes a block connection atomic.
        self._db = sqlite3.connect(path, check_same_thread=False,
                                   isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=OFF")
        self._db.execute("PRAGMA cache_size=-16000")
        with self._lock:
            self._create_schema()
            v = self.get_meta("schema")
            if v is not None and int.from_bytes(v, "little") != SCHEMA_VERSION:
                with self.transaction():
                    self._wipe()
                    self.set_meta("schema", struct.pack("<I", SCHEMA_VERSION))
            elif v is None:
                self.set_meta("schema", struct.pack("<I", SCHEMA_VERSION))

    def _create_schema(self):
        for stmt in SCHEMA:
            self._db.execute(stmt)

    def _wipe(self):
        """Drop all tables (incompatible schema found) and recreate."""
        for t in _TABLES:
            self._db.execute(f"DROP TABLE IF EXISTS {t}")
        self._create_schema()

    @contextlib.contextmanager
    def transaction(self):
        """Run a block of statements as ONE atomic SQLite transaction.

        Nested use is a no-op (SQLite has no real nested transactions): the
        inner block joins the outer transaction, so callers can compose the
        helpers here without splitting an atomic transition in two.
        """
        with self._lock:
            depth = getattr(self._local_depth, "n", 0)
            if depth == 0:
                self._db.execute("BEGIN IMMEDIATE")
            self._local_depth.n = depth + 1
            try:
                yield self
            except BaseException:
                self._local_depth.n = depth
                if depth == 0:
                    with contextlib.suppress(sqlite3.OperationalError):
                        self._db.execute("ROLLBACK")
                raise
            else:
                self._local_depth.n = depth
                if depth == 0:
                    self._db.execute("COMMIT")

    def commit(self):
        """Kept for API compatibility; `transaction()` owns the commit."""
        with self._lock:
            with contextlib.suppress(sqlite3.OperationalError):
                self._db.execute("COMMIT")

    def rollback(self):
        with self._lock:
            try:
                self._db.execute("ROLLBACK")
            except sqlite3.OperationalError:
                pass

    def close(self):
        with self._lock:
            try:
                self._db.execute("COMMIT")
            except sqlite3.OperationalError:
                pass
            self._db.close()

    # ------------------------------------------------------------------
    # meta
    # ------------------------------------------------------------------
    def get_meta(self, key: str) -> Optional[bytes]:
        with self._lock:
            row = self._db.execute("SELECT value FROM meta WHERE key=?",
                                   (key,)).fetchone()
            return None if row is None else row[0]

    def set_meta(self, key: str, value: bytes):
        """Write a meta row inside the caller's transaction (no implicit
        commit; `commit()` finalises the whole transition)."""
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)",
                             (key, value))

    def set_meta_committed(self, key: str, value: bytes):
        """Deprecated alias for `set_meta` (autocommit mode)."""
        self.set_meta(key, value)

    # ------------------------------------------------------------------
    # blocks
    # ------------------------------------------------------------------
    def put_block(self, block: Block, work: Optional[int]):
        """Store a block with its cumulative work (None = unknown/orphan)."""
        with self.transaction():
            self._insert_block(block, work)

    def set_block_work(self, block_hash: bytes, work: int):
        with self.transaction():
            self._db.execute("UPDATE blocks SET work=? WHERE hash=?",
                             (_pack_work(work), block_hash))

    def remove_block(self, block_hash: bytes):
        """Delete a block and its tx index entries (invalid side chains)."""
        with self.transaction():
            row = self._db.execute("SELECT raw FROM blocks WHERE hash=?",
                                   (block_hash,)).fetchone()
            if row is None:
                return
            blk = Block.deserialize(row[0])
            for tx in blk.transactions:
                self._db.execute(
                    "DELETE FROM tx_index WHERE txid=? AND hash=?",
                    (tx.txid(), block_hash))
            self._db.execute("DELETE FROM blocks WHERE hash=?", (block_hash,))

    def get_block_by_hash(self, block_hash: bytes) -> Optional[Block]:
        raw = self.block_raw(block_hash)
        return None if raw is None else Block.deserialize(raw)

    def block_raw(self, block_hash: bytes) -> Optional[bytes]:
        with self._lock:
            row = self._db.execute("SELECT raw FROM blocks WHERE hash=?",
                                   (block_hash,)).fetchone()
            return None if row is None else row[0]

    def set_main_block(self, height: int, block_hash: bytes):
        with self.transaction():
            self._db.execute("INSERT OR REPLACE INTO main_chain VALUES (?, ?)",
                             (height, block_hash))

    def truncate_main_chain(self, from_height: int):
        with self.transaction():
            self._db.execute("DELETE FROM main_chain WHERE height >= ?",
                             (from_height,))

    def get_main_hash_at_height(self, height: int) -> Optional[bytes]:
        with self._lock:
            row = self._db.execute("SELECT hash FROM main_chain WHERE height=?",
                                   (height,)).fetchone()
            return None if row is None else row[0]

    def main_chain_height(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT MAX(height) FROM main_chain").fetchone()
            return -1 if row is None or row[0] is None else int(row[0])

    def get_block_by_height(self, height: int) -> Optional[Block]:
        with self._lock:
            # canonical block on the main chain first
            row = self._db.execute(
                "SELECT b.raw FROM main_chain m JOIN blocks b ON m.hash = b.hash "
                "WHERE m.height=?", (height,)).fetchone()
            if row is None:
                # fall back to any stored block (header-only queries)
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
            if row is None or row[1] is None:
                return None
            w = _unpack_work(row[1])
            if w <= min_work:
                return None
            return row[0], w

    def children_of(self, block_hash: bytes) -> List[bytes]:
        with self._lock:
            return [r[0] for r in self._db.execute(
                "SELECT hash FROM blocks WHERE parent=?", (block_hash,)).fetchall()]

    def get_main_tips(self):
        """[(height, hash)] for every main-chain height that has no child on
        the main chain, i.e. the fork points a competing chain can diverge
        from.  Used by getchaintips."""
        with self._lock:
            return self._db.execute(
                "SELECT m.height, m.hash FROM main_chain m "
                "LEFT JOIN main_chain c ON c.height = m.height + 1 "
                "WHERE c.height IS NULL ORDER BY m.height").fetchall()

    def has_blocks(self) -> bool:
        """True when ANY block is stored (any chain, any genesis)."""
        with self._lock:
            row = self._db.execute("SELECT 1 FROM blocks LIMIT 1").fetchone()
            return row is not None

    def raw_main_chain(self):
        """[(height, hash)] for the whole canonical index, oldest first.

        Read without the chain lock's callers mutating anything, so a replay
        can snapshot the index and then rewrite it in one transaction.
        """
        with self._lock:
            return self._db.execute(
                "SELECT height, hash FROM main_chain ORDER BY height"
            ).fetchall()

    def count_blocks(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]

    def count_utxos(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM utxos").fetchone()[0]

    # ------------------------------------------------------------------
    # transactions
    # ------------------------------------------------------------------
    def get_tx_block(self, txid: bytes) -> Optional[Tuple[int, bytes]]:
        """(height, block_hash) for a transaction that is on the MAIN chain.

        A txid may exist on a competing side chain too; when the indexed block
        is no longer canonical the lookup falls through to the main-chain
        index so explorers never report a side-chain block as confirmed.
        """
        with self._lock:
            row = self._db.execute("SELECT height, hash FROM tx_index WHERE txid=?",
                                   (txid,)).fetchone()
            if row is None:
                return None
            mh = self.get_main_hash_at_height(row[0])
            if mh is not None and mh == row[1]:
                return row[0], row[1]
            for r in self._db.execute(
                    "SELECT b.height, b.hash FROM blocks b "
                    "JOIN main_chain m ON m.hash = b.hash "
                    "WHERE b.height = ?", (row[0],)).fetchall():
                blk = self.get_block_by_hash(r[1])
                if blk is None:
                    continue
                if any(tx.txid() == txid for tx in blk.transactions):
                    return r[0], r[1]
            return None

    def get_transactions_at_height(self, height: int, block_hash: bytes) -> List:
        blk = self.get_block_by_hash(block_hash)
        return [] if blk is None else blk.transactions

    # ------------------------------------------------------------------
    # block-atomic state transitions
    # ------------------------------------------------------------------
    def init_genesis(self, block: Block, work: int, state: ChainState):
        with self.transaction():
            self._insert_block(block, work)
            self._db.execute("INSERT OR REPLACE INTO main_chain VALUES (?, ?)",
                             (0, block.hash))
            self._replace_full_state(state)
            self.set_meta("tip", block.hash)
            self.set_meta("tip_height", struct.pack("<Q", 0))

    def connect_block(self, block: Block, work: int, spent, created, nonces):
        """Atomically connect one main-chain block: block row, canonical
        index entry, UTXO delta, nonce delta and the tip pointers all land in
        a single transaction."""
        with self.transaction():
            self._insert_block(block, work)
            self._db.execute("INSERT OR REPLACE INTO main_chain VALUES (?, ?)",
                             (block.height, block.hash))
            self._apply_delta(spent, created, nonces)
            self.set_meta("tip", block.hash)
            self.set_meta("tip_height", struct.pack("<Q", block.height))

    def reorganize(self, main_chain: List[Tuple[int, bytes]], state: ChainState,
                   tip_hash: bytes, tip_height: int):
        """Atomically switch the canonical chain to `main_chain` (oldest
        first) and rewrite the full UTXO/nonce tables from `state`."""
        with self.transaction():
            if main_chain:
                self._db.execute("DELETE FROM main_chain WHERE height >= ?",
                                 (main_chain[0][0],))
            else:
                self._db.execute("DELETE FROM main_chain")
            self._db.executemany(
                "INSERT OR REPLACE INTO main_chain VALUES (?, ?)",
                list(main_chain))
            self._replace_full_state(state)
            self.set_meta("tip", tip_hash)
            self.set_meta("tip_height", struct.pack("<Q", tip_height))

    def _insert_block(self, block: Block, work: Optional[int]):
        self._db.execute(
            "INSERT OR REPLACE INTO blocks VALUES (?, ?, ?, ?, ?)",
            (block.hash, block.height, block.header.prev_hash,
             block.serialize(),
             None if work is None else _pack_work(work)))
        self._db.executemany(
            "INSERT OR REPLACE INTO tx_index VALUES (?, ?, ?)",
            [(tx.txid(), block.height, block.hash)
             for tx in block.transactions])

    def _apply_delta(self, spent, created, nonces):
        for (txid, idx) in spent:
            self._db.execute("DELETE FROM utxos WHERE txid=? AND idx=?",
                             (txid, idx))
        self._db.executemany(
            "INSERT OR REPLACE INTO utxos VALUES (?, ?, ?, ?, ?, ?)",
            [(txid, idx, u.addr_hash, u.value, 1 if u.is_coinbase else 0,
              u.cb_height) for (txid, idx), u in created])
        self._db.executemany(
            "INSERT OR REPLACE INTO nonces VALUES (?, ?)", list(nonces))

    def _replace_full_state(self, state: ChainState):
        self._db.execute("DELETE FROM utxos")
        self._db.execute("DELETE FROM nonces")
        self._db.executemany(
            "INSERT INTO utxos VALUES (?, ?, ?, ?, ?, ?)",
            [(txid, idx, u.addr_hash, u.value, 1 if u.is_coinbase else 0,
              u.cb_height) for (txid, idx), u in state.utxos.items()])
        self._db.executemany("INSERT OR REPLACE INTO nonces VALUES (?, ?)",
                             list(state.nonces.items()))

    # ------------------------------------------------------------------
    # back-compat thin wrappers (single-shot transactions)
    # ------------------------------------------------------------------
    def apply_block_delta(self, block, spent, created, nonces, tip_hash,
                          tip_height):
        with self.transaction():
            self._apply_delta(spent, created, nonces)
            self.set_meta("tip", tip_hash)
            self.set_meta("tip_height", struct.pack("<Q", tip_height))

    def save_state(self, state: ChainState, tip_hash: bytes, tip_height: int):
        """Full state snapshot (explicit checkpoint / repair)."""
        with self.transaction():
            self._replace_full_state(state)
            self.set_meta("tip", tip_hash)
            self.set_meta("tip_height", struct.pack("<Q", tip_height))

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
            for op, u in state.utxos.items():
                state._index_add(op, u)
            th = self.get_meta("tip_height")
            tip_height = struct.unpack("<Q", th)[0] if th else 0
            return state, tip, tip_height

    def verify_main_chain(self, genesis_hash: bytes) -> Tuple[bool, str]:
        """Check the canonical index is a contiguous genesis-rooted chain.

        Returns (ok, reason).  A store that fails this check must be
        reindexed rather than trusted, because the UTXO tables are only
        meaningful when the index they were written against is intact.
        """
        with self._lock:
            height = self.main_chain_height()
            if height < 0:
                return False, "canonical index is empty"
            row = self._db.execute(
                "SELECT hash FROM main_chain WHERE height=0").fetchone()
            if row is None or row[0] != genesis_hash:
                return False, "canonical index does not start at genesis"
            rows = self._db.execute(
                "SELECT height, hash FROM main_chain ORDER BY height").fetchall()
            if len(rows) != height + 1:
                return False, f"canonical index has gaps (max {height}, {len(rows)} rows)"
            prev = None
            for h, hsh in rows:
                raw = self._db.execute("SELECT parent, height FROM blocks WHERE hash=?",
                                       (hsh,)).fetchone()
                if raw is None:
                    return False, f"missing block row at height {h}"
                if raw[1] != h:
                    return False, f"block {hsh.hex()[:16]} height mismatch at index {h}"
                if prev is not None and raw[0] != prev:
                    return False, f"broken parent link at height {h}"
                prev = hsh
            return True, "ok"

    def prune_side_chains(self, keep_work_above: int = 0) -> int:
        """Delete stored blocks that are not on the main chain and carry no
        useful work (used by `qeuph reindex --prune`)."""
        with self.transaction():
            main = {r[0] for r in self._db.execute("SELECT hash FROM main_chain")}
            rows = self._db.execute(
                "SELECT hash, work FROM blocks WHERE work IS NOT NULL").fetchall()
            doomed = [h for h, w in rows
                      if h not in main and _unpack_work(w) <= keep_work_above]
            for h in doomed:
                self._db.execute("DELETE FROM blocks WHERE hash=?", (h,))
            self._db.execute("DELETE FROM tx_index WHERE hash NOT IN "
                             "(SELECT hash FROM main_chain)")
            return len(doomed)

    def drop_side_chains(self) -> int:
        """Delete every block that is not on the canonical main chain."""
        with self.transaction():
            main = {r[0] for r in self._db.execute("SELECT hash FROM main_chain")}
            rows = [r[0] for r in self._db.execute("SELECT hash FROM blocks")]
            doomed = [h for h in rows if h not in main]
            for h in doomed:
                self._db.execute("DELETE FROM blocks WHERE hash=?", (h,))
            self._db.execute("DELETE FROM tx_index WHERE hash NOT IN "
                             "(SELECT hash FROM main_chain)")
            return len(doomed)

    def truncate_to_height(self, height: int) -> int:
        """Delete canonical blocks above `height` (rollback without reorg)."""
        with self.transaction():
            doomed = [r[0] for r in self._db.execute(
                "SELECT b.hash FROM blocks b JOIN main_chain m ON m.hash=b.hash "
                "WHERE m.height > ?", (height,)).fetchall()]
            self._db.execute("DELETE FROM main_chain WHERE height > ?", (height,))
            for h in doomed:
                self._db.execute("DELETE FROM blocks WHERE hash=?", (h,))
            self._db.execute("DELETE FROM tx_index WHERE hash NOT IN "
                             "(SELECT hash FROM main_chain)")
            return len(doomed)

    # ------------------------------------------------------------------
    # peer bans
    # ------------------------------------------------------------------
    def ban_peer(self, addr: str, until: float, score: int, reason: str = ""):
        with self.transaction():
            self._db.execute("INSERT OR REPLACE INTO bans VALUES (?, ?, ?, ?)",
                             (addr, float(until), int(score), reason))
            self._db.execute("DELETE FROM bans WHERE until < ?",
                             (time.time() - 3600,))

    def is_banned(self, addr: str) -> bool:
        with self._lock:
            row = self._db.execute("SELECT until FROM bans WHERE addr=?",
                                   (addr,)).fetchone()
            return row is not None and row[0] > time.time()

    def clear_bans(self) -> int:
        with self.transaction():
            n = self._db.execute("SELECT COUNT(*) FROM bans").fetchone()[0]
            self._db.execute("DELETE FROM bans")
            return n

    def ban_count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM bans").fetchone()[0]

    def list_bans(self):
        with self._lock:
            return self._db.execute(
                "SELECT addr, until, score, reason FROM bans "
                "WHERE until > ?", (time.time(),)).fetchall()

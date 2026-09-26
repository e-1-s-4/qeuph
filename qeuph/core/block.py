"""
Blocks and headers (whitepaper section 4.1).

Header layout (fixed 168 bytes, all little-endian):
    version      4 bytes
    prev_hash   64 bytes   double SHA3-512
    merkle_root 64 bytes   double SHA3-512
    timestamp    8 bytes
    bits         4 bytes   compact target
    height       8 bytes
    nonce       16 bytes   PoW search space

block hash = double SHA3-512(header).  A block is valid when the hash as a
big-endian integer is below the target in `bits`.
"""
from __future__ import annotations

import struct
import time
from typing import List, Optional

from qeuph import constants as C
from qeuph.core import merkle as merkle_mod
from qeuph.core import pow as pow_mod
from qeuph.core.tx import Transaction

HEADER_SIZE = 4 + 64 + 64 + 8 + 4 + 8 + 16


class BlockHeader:
    __slots__ = ("version", "prev_hash", "merkle_root", "timestamp",
                 "bits", "height", "nonce", "_hash_cache")

    def __init__(self, version: int, prev_hash: bytes, merkle_root: bytes,
                 timestamp: int, bits: int, height: int, nonce: int = 0):
        self.version = version
        self.prev_hash = prev_hash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.height = height
        self.nonce = nonce
        self._hash_cache: Optional[bytes] = None

    def serialize(self) -> bytes:
        return b"".join([
            struct.pack("<I", self.version),
            self.prev_hash,
            self.merkle_root,
            struct.pack("<Q", self.timestamp),
            struct.pack("<I", self.bits),
            struct.pack("<Q", self.height),
            self.nonce.to_bytes(16, "little"),
        ])

    def hash(self) -> bytes:
        if self._hash_cache is None:
            self._hash_cache = pow_mod.header_hash(self.serialize())
        return self._hash_cache

    @classmethod
    def deserialize(cls, raw: bytes) -> "BlockHeader":
        if len(raw) != HEADER_SIZE:
            raise ValueError("bad header size")
        version = struct.unpack("<I", raw[0:4])[0]
        prev_hash = raw[4:68]
        merkle_root = raw[68:132]
        timestamp = struct.unpack("<Q", raw[132:140])[0]
        bits = struct.unpack("<I", raw[140:144])[0]
        height = struct.unpack("<Q", raw[144:152])[0]
        nonce = int.from_bytes(raw[152:168], "little")
        return cls(version, prev_hash, merkle_root, timestamp, bits, height, nonce)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "prev_hash": self.prev_hash.hex(),
            "merkle_root": self.merkle_root.hex(),
            "timestamp": self.timestamp,
            "bits": hex(self.bits),
            "difficulty": pow_mod.difficulty_from_bits(self.bits),
            "height": self.height,
            "nonce": self.nonce,
            "hash": self.hash().hex(),
        }


class Block:
    __slots__ = ("header", "transactions")

    def __init__(self, header: BlockHeader, transactions: List[Transaction]):
        self.header = header
        self.transactions = transactions

    # ------------------------------------------------------------------
    @property
    def height(self) -> int:
        return self.header.height

    @property
    def hash(self) -> bytes:
        return self.header.hash()

    def txids(self) -> List[bytes]:
        return [tx.txid() for tx in self.transactions]

    def serialize(self) -> bytes:
        out = bytearray()
        out += self.header.serialize()
        out += struct.pack("<I", len(self.transactions))
        for tx in self.transactions:
            raw = tx.serialize()
            out += struct.pack("<I", len(raw)) + raw
        return bytes(out)

    def block_size(self) -> int:
        return HEADER_SIZE + 4 + sum(4 + len(tx.serialize()) for tx in self.transactions)

    # ------------------------------------------------------------------
    @classmethod
    def deserialize(cls, raw: bytes) -> "Block":
        pos = 0

        def take(n):
            nonlocal pos
            if pos + n > len(raw):
                raise ValueError("block truncated")
            b = raw[pos:pos + n]
            pos += n
            return b

        header = BlockHeader.deserialize(take(HEADER_SIZE))
        n_tx = struct.unpack("<I", take(4))[0]
        if n_tx > 10000:
            raise ValueError("too many transactions")
        txs = []
        for _ in range(n_tx):
            ln = struct.unpack("<I", take(4))[0]
            txs.append(Transaction.deserialize(take(ln)))
        if pos != len(raw):
            raise ValueError("trailing bytes in block")
        return cls(header, txs)

    # ------------------------------------------------------------------
    @classmethod
    def build(cls, prev_hash: bytes, height: int, bits: int, transactions: List[Transaction],
              timestamp: Optional[int] = None, version: int = C.BLOCK_VERSION,
              min_timestamp: int = 0) -> "Block":
        """Assemble an unmined block (nonce = 0)."""
        ts = int(timestamp if timestamp is not None else time.time())
        if ts < min_timestamp:
            ts = min_timestamp
        root = merkle_mod.merkle_root([tx.txid() for tx in transactions])
        header = BlockHeader(version, prev_hash, root, ts, bits, height, 0)
        return cls(header, transactions)

    def mine(self, max_attempts: int = 1 << 34) -> "Block":
        """Fill in the PoW nonce in place."""
        base = self.header.serialize()
        self.header.nonce = pow_mod.mine_header(base, self.header.bits,
                                                max_attempts=max_attempts)
        self.header._hash_cache = None
        return self

    # ------------------------------------------------------------------
    def to_dict(self, hrp: str = "quh") -> dict:
        d = self.header.to_dict()
        d["tx_count"] = len(self.transactions)
        d["txids"] = [t.hex() for t in self.txids()]
        d["transactions"] = [tx.to_dict(hrp) for tx in self.transactions]
        d["size"] = self.block_size()
        return d

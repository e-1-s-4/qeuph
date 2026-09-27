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

A block serializes as the 168-byte header, a uint32 transaction count and
then, for each transaction, a uint32 length followed by the canonical
transaction bytes (whitepaper Appendix A).  Parsing is strict: any trailing
byte, oversized count or truncated field raises ValueError so a malformed
block can never be silently accepted.
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

    def set_nonce(self, nonce: int):
        self.nonce = nonce
        self._hash_cache = None

    def meets_target(self) -> bool:
        try:
            return pow_mod.check_pow(self.serialize(), self.bits)
        except ValueError:
            return False

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
        return HEADER_SIZE + 4 + sum(4 + len(tx.serialize())
                                     for tx in self.transactions)

    # ------------------------------------------------------------------
    @classmethod
    def deserialize(cls, raw: bytes) -> "Block":
        if len(raw) < HEADER_SIZE + 4:
            raise ValueError("block truncated")
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
        if n_tx == 0 or n_tx > C.MAX_BLOCK_TXS:
            raise ValueError("bad transaction count")
        txs = []
        for _ in range(n_tx):
            ln = struct.unpack("<I", take(4))[0]
            if ln == 0 or ln > C.MAX_TX_SIZE:
                raise ValueError("bad transaction length")
            txs.append(Transaction.deserialize(take(ln)))
        if pos != len(raw):
            raise ValueError("trailing bytes in block")
        if len(raw) > C.MAX_BLOCK_SIZE:
            raise ValueError("block too large")
        return cls(header, txs)

    # ------------------------------------------------------------------
    @classmethod
    def build(cls, prev_hash: bytes, height: int, bits: int,
              transactions: List[Transaction],
              timestamp: Optional[int] = None,
              version: int = C.BLOCK_VERSION,
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
        self.header.set_nonce(
            pow_mod.mine_header(self.header.serialize(), self.header.bits,
                                max_attempts=max_attempts))
        return self

    def mine_from(self, start_nonce: int, count: int) -> Optional[int]:
        """Search the nonce space [start_nonce, start_nonce+count); returns
        the winning nonce and sets it, or None when the slice is exhausted."""
        for nonce in pow_mod.mine_range(self.header.serialize(),
                                        self.header.bits, start_nonce, count):
            self.header.set_nonce(nonce)
            return nonce
        return None

    # ------------------------------------------------------------------
    def to_dict(self, hrp: str = "quh") -> dict:
        d = self.header.to_dict()
        d["tx_count"] = len(self.transactions)
        d["txids"] = [t.hex() for t in self.txids()]
        d["transactions"] = [tx.to_dict(hrp) for tx in self.transactions]
        d["size"] = self.block_size()
        return d

    def summary(self, hrp: str = "quh", confirmations: int = 1) -> dict:
        """Header plus summary fields, without the full tx list (block index)."""
        d = self.header.to_dict()
        d["tx_count"] = len(self.transactions)
        d["size"] = self.block_size()
        d["confirmations"] = confirmations
        from qeuph.core.state import confirmations
        coinbase = self.transactions[0] if self.transactions else None
        if coinbase is not None:
            d["coinbase_data"] = coinbase.inputs[0].data.decode(
                "utf-8", "replace") if coinbase.inputs else ""
            d["miner_payout"] = coinbase.total_out
            if coinbase.outputs:
                from qeuph.crypto.address import hash_to_address
                d["miner_address"] = hash_to_address(
                    coinbase.outputs[0].addr_hash, hrp)
        return d

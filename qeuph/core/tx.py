"""
Qeuph transaction model: UTXO + txnonce hybrid (whitepaper section 2).

A transaction spends previously unspent outputs (UTXO model) and carries a
per-address txnonce on every input.  The txnonce enforces strict ordering
and replay protection for each address independent of which UTXO is spent:

    valid input.txnonce == chain_nonce(address) + 1      (first use: 1)

Each input is authorized by an ML-DSA-87 signature over the double
SHA3-512 digest of the signature-less transaction prefix plus the input
index.  Transaction ids are the double SHA3-512 of the full serialization.

Coinbase transactions have no signature; their single pseudo-input carries
the block height (BIP-34 style) and up to 256 bytes of miner data.
"""
from __future__ import annotations

import struct
from typing import List, Optional

from qeuph import constants as C
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa

ZERO_TXID = bytes(64)
COINBASE_INDEX = 0xFFFFFFFF
MAX_COINBASE_DATA = 256
MAX_U64 = (1 << 64) - 1
MAX_U32 = (1 << 32) - 1


class TxIn:
    __slots__ = ("prev_txid", "prev_index", "txnonce", "pubkey", "signature", "data")

    def __init__(self, prev_txid: bytes, prev_index: int, txnonce: int,
                 pubkey: bytes = b"", signature: bytes = b"", data: bytes = b""):
        self.prev_txid = prev_txid
        self.prev_index = prev_index
        self.txnonce = txnonce
        self.pubkey = pubkey
        self.signature = signature
        self.data = data          # only for coinbase pseudo-input

    @property
    def is_coinbase(self) -> bool:
        return self.prev_txid == ZERO_TXID and self.prev_index == COINBASE_INDEX

    def _check(self):
        if len(self.prev_txid) != 64:
            raise ValueError("prev_txid must be 64 bytes")
        if not (0 <= self.prev_index <= MAX_U32):
            raise ValueError("prev_index out of range")
        if not (0 <= self.txnonce <= MAX_U64):
            raise ValueError("txnonce out of range")

    def serialize_sigless(self) -> bytes:
        # pubkey IS committed; signature is not (it covers the digest)
        out = bytearray()
        out += self.prev_txid
        out += struct.pack("<I", self.prev_index)
        out += struct.pack("<Q", self.txnonce)
        if self.is_coinbase:
            out += struct.pack("<H", len(self.data)) + self.data
        else:
            out += struct.pack("<H", len(self.pubkey)) + self.pubkey
        return bytes(out)

    def serialize(self) -> bytes:
        out = bytearray()
        out += self.prev_txid
        out += struct.pack("<I", self.prev_index)
        out += struct.pack("<Q", self.txnonce)
        if self.is_coinbase:
            out += struct.pack("<H", len(self.data)) + self.data
        else:
            out += struct.pack("<H", len(self.pubkey)) + self.pubkey
            out += struct.pack("<H", len(self.signature)) + self.signature
        return bytes(out)

    def __repr__(self):
        return f"TxIn({self.prev_txid.hex()[:12]}..:{self.prev_index} n={self.txnonce})"


class TxOut:
    __slots__ = ("value", "addr_hash")

    def __init__(self, value: int, addr_hash: bytes):
        self.value = value
        self.addr_hash = addr_hash

    def serialize(self) -> bytes:
        if not (0 <= self.value <= MAX_U64):
            raise ValueError("output value out of range")
        if len(self.addr_hash) != 64:
            raise ValueError("output address hash must be 64 bytes")
        return struct.pack("<Q", self.value) + self.addr_hash

    def __repr__(self):
        return f"TxOut({self.value} -> {self.addr_hash.hex()[:12]}..)"


class Transaction:
    # cached ids are invalidated by _touch() whenever the tx mutates
    __slots__ = ("version", "inputs", "outputs", "lock_time",
                 "_txid_cache", "_sigless_cache")

    def __init__(self, inputs: List[TxIn], outputs: List[TxOut],
                 version: int = C.TX_VERSION, lock_time: int = 0):
        self.version = version
        self.inputs = inputs
        self.outputs = outputs
        self.lock_time = lock_time
        self._txid_cache: Optional[bytes] = None
        self._sigless_cache: Optional[bytes] = None

    def _touch(self):
        """Invalidate caches after a mutation (signing etc.)."""
        self._txid_cache = None
        self._sigless_cache = None

    # ------------------------------------------------------------------
    @property
    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0].is_coinbase

    def _check(self):
        if not (0 <= self.version <= MAX_U32):
            raise ValueError("version out of range")
        if not (0 <= self.lock_time <= MAX_U64):
            raise ValueError("lock_time out of range")
        if not self.inputs or not self.outputs:
            raise ValueError("transaction needs at least one input and output")
        for i in self.inputs:
            i._check()

    def sigless_bytes(self) -> bytes:
        if self._sigless_cache is not None:
            return self._sigless_cache
        out = bytearray()
        out += struct.pack("<I", self.version)
        out += struct.pack("<I", len(self.inputs))
        for i in self.inputs:
            out += i.serialize_sigless()
        out += struct.pack("<I", len(self.outputs))
        for o in self.outputs:
            out += o.serialize()
        out += struct.pack("<Q", self.lock_time)
        self._sigless_cache = bytes(out)
        return self._sigless_cache

    def serialize(self) -> bytes:
        self._check()
        out = bytearray()
        out += struct.pack("<I", self.version)
        out += struct.pack("<I", len(self.inputs))
        for i in self.inputs:
            out += i.serialize()
        out += struct.pack("<I", len(self.outputs))
        for o in self.outputs:
            out += o.serialize()
        out += struct.pack("<Q", self.lock_time)
        return bytes(out)

    def txid(self) -> bytes:
        """Double SHA3-512 of the full serialization (whitepaper 2.1)."""
        if self._txid_cache is not None:
            return self._txid_cache
        from qeuph.crypto.address import dhash
        self._txid_cache = dhash(self.serialize())
        return self._txid_cache

    def cached_txid(self) -> bytes:
        """txid() for already-built transactions (cache-friendly alias)."""
        return self.txid()

    def signing_message(self, input_index: int) -> bytes:
        from qeuph.crypto.address import dhash
        return dhash(self.sigless_bytes()) + struct.pack("<I", input_index)

    # ------------------------------------------------------------------
    def sign(self, keys) -> "Transaction":
        """Sign every non-coinbase input.

        `keys`: list (same length as inputs) whose elements are either a
        32-byte seed (preferred, fast path) or a full 4896-byte sk blob.
        Entries for coinbase inputs are ignored (use None).

        Two-pass: all pubkeys are placed first so that every signature
        covers the complete transaction (including the other inputs'
        pubkeys).
        """
        from qeuph.crypto import fips204
        # One key per input, enforced.  `zip` would silently stop at the
        # shorter list, leaving the remaining inputs unsigned - a transaction
        # that every node rejects and that looks signed in every log line.
        keys = list(keys)
        if len(keys) != len(self.inputs):
            raise ValueError(
                f"sign() needs one key per input ({len(self.inputs)} inputs, "
                f"{len(keys)} keys given)")
        for idx, (inp, key) in enumerate(zip(self.inputs, keys)):
            if inp.is_coinbase or key is None:
                continue
            if len(key) == ml_dsa.SEED_SIZE:
                inp.pubkey = ml_dsa.pk_from_sk_seed(key)
            elif len(key) == ml_dsa.SK_SIZE:
                inp.pubkey = fips204.pk_from_sk(key)
            else:
                raise ValueError("bad key material length")
        self._touch()
        for idx, (inp, key) in enumerate(zip(self.inputs, keys)):
            if inp.is_coinbase or key is None:
                continue
            msg = self.signing_message(idx)
            if len(key) == ml_dsa.SEED_SIZE:
                inp.signature = ml_dsa.sign_with_seed(key, msg)
            else:
                inp.signature = fips204.sign(key, msg, deterministic=False)
            self._touch()
        return self

    def sign_input(self, input_index: int, seed: bytes) -> None:
        inp = self.inputs[input_index]
        inp.pubkey = ml_dsa.pk_from_sk_seed(seed)
        msg = self.signing_message(input_index)
        inp.signature = ml_dsa.sign_with_seed(seed, msg)
        self._touch()

    # ------------------------------------------------------------------
    @property
    def total_out(self) -> int:
        return sum(o.value for o in self.outputs)

    def size(self) -> int:
        return len(self.serialize())

    def __repr__(self):
        kind = "coinbase" if self.is_coinbase else "tx"
        return (f"Transaction({kind}, {len(self.inputs)} in, {len(self.outputs)} out, "
                f"{self.total_out} quphi out)")

    # ------------------------------------------------------------------
    @classmethod
    def deserialize(cls, raw: bytes, allow_unsigned: bool = False) -> "Transaction":
        """Parse the canonical encoding.

        `allow_unsigned` accepts inputs whose pubkey/signature are still zero
        length, which is what `createrawtransaction` emits and what a
        wallet needs before signing.  Consensus paths never set it: a block
        input must carry a full ML-DSA-87 key and signature.
        """
        pos = 0

        def take(n):
            nonlocal pos
            if pos + n > len(raw):
                raise ValueError("transaction truncated")
            b = raw[pos:pos + n]
            pos += n
            return b

        version = struct.unpack("<I", take(4))[0]
        n_in = struct.unpack("<I", take(4))[0]
        if n_in == 0 or n_in > C.MAX_TX_INPUTS:
            raise ValueError("bad input count")
        inputs = []
        for _ in range(n_in):
            prev_txid = take(64)
            prev_index = struct.unpack("<I", take(4))[0]
            txnonce = struct.unpack("<Q", take(8))[0]
            is_cb = prev_txid == ZERO_TXID and prev_index == COINBASE_INDEX
            dlen = struct.unpack("<H", take(2))[0]
            blob = take(dlen) if dlen else b""
            if is_cb:
                if dlen > MAX_COINBASE_DATA:
                    raise ValueError("coinbase data too long")
                inputs.append(TxIn(prev_txid, prev_index, txnonce, data=blob))
            else:
                if dlen not in (0, ml_dsa.PK_SIZE):
                    raise ValueError("bad pubkey length")
                if dlen == 0 and not allow_unsigned:
                    raise ValueError("missing pubkey")
                pubkey = blob
                slen = struct.unpack("<H", take(2))[0]
                if slen not in (0, ml_dsa.SIG_SIZE):
                    raise ValueError("bad signature length")
                if slen == 0 and not allow_unsigned:
                    raise ValueError("missing signature")
                sig = take(slen) if slen else b""
                inputs.append(TxIn(prev_txid, prev_index, txnonce,
                                   pubkey=pubkey, signature=sig))
        n_out = struct.unpack("<I", take(4))[0]
        if n_out == 0 or n_out > C.MAX_TX_OUTPUTS:
            raise ValueError("bad output count")
        outputs = []
        for _ in range(n_out):
            value = struct.unpack("<Q", take(8))[0]
            addr_hash = take(64)
            outputs.append(TxOut(value, addr_hash))
        lock_time = struct.unpack("<Q", take(8))[0]
        if pos != len(raw):
            raise ValueError("trailing bytes in transaction")
        return cls(inputs, outputs, version, lock_time)

    # ------------------------------------------------------------------
    def to_dict(self, hrp: str = "quh") -> dict:
        return {
            "txid": self.txid().hex(),
            "version": self.version,
            "coinbase": self.is_coinbase,
            "inputs": [{
                "prev_txid": i.prev_txid.hex(),
                "prev_index": i.prev_index,
                "txnonce": i.txnonce,
                "pubkey": i.pubkey.hex()[:32] + ("..." if len(i.pubkey) > 32 else ""),
                "signature": i.signature.hex()[:32] + ("..." if len(i.signature) > 32 else ""),
                "data": i.data.hex() if i.data else "",
                "data_text": (i.data.decode("utf-8", "replace")
                              if i.data else ""),
            } for i in self.inputs],
            "outputs": [{
                "value": o.value,
                "value_quh": o.value / C.QUPHI_PER_QUH,
                "address": addr_mod.hash_to_address(o.addr_hash, hrp),
            } for o in self.outputs],
            "lock_time": self.lock_time,
            "size": self.size(),
        }


def make_coinbase(height: int, addr_hash: bytes, reward_with_fees: int,
                  data: bytes = b"") -> Transaction:
    """Build the coinbase transaction paying the miner.

    `data` is up to 256 bytes of miner-chosen extra nonce; it commits the
    miner and worker to the block so parallel workers never collide on the
    same template.
    """
    if len(data) > MAX_COINBASE_DATA:
        raise ValueError("coinbase data too long")
    if not (0 <= reward_with_fees <= MAX_U64):
        raise ValueError("coinbase reward out of range")
    inp = TxIn(ZERO_TXID, COINBASE_INDEX, height, data=data)
    outs = [TxOut(reward_with_fees, addr_hash)] if reward_with_fees > 0 else []
    return Transaction([inp], outs)

"""
Wallet key derivation.

A Qeuph wallet stores one 32-byte master seed.  Address i is derived by

    seed_i = SHA3-512(master_seed || LE32(i))[:32]
    (pk_i, sk_i) = ML-DSA-87.KeyGen(seed_i)          [FIPS 204 seeded]
    address_i = bech32m("quh", double-SHA3-512(pk_i))

mirroring QRL's wallet (one XMSS tree per address) with ML-DSA seeds
instead of Merkle trees.  The public key (and address) derive on the fast
backend when available; the expanded sk blob is materialised lazily since
signing goes through the seed path.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional

from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa


def derive_seed(master_seed: bytes, index: int) -> bytes:
    if len(master_seed) != 32:
        raise ValueError("master seed must be 32 bytes")
    return hashlib.sha3_512(master_seed + index.to_bytes(4, "little")).digest()[:32]


class WalletKey:
    """Material for one derived address."""

    __slots__ = ("index", "seed", "hrp", "_pk", "_sk")

    def __init__(self, index: int, seed: bytes, hrp: str = "quh"):
        self.index = index
        self.seed = seed
        self.hrp = hrp
        self._pk: Optional[bytes] = None
        self._sk: Optional[bytes] = None

    # ------------------------------------------------------------------
    @property
    def pk(self) -> bytes:
        if self._pk is None:
            self._pk = ml_dsa.pk_from_seed(self.seed)
        return self._pk

    @property
    def sk(self) -> bytes:
        if self._sk is None:
            self._sk = ml_dsa.keypair_from_seed(self.seed)[1]
        return self._sk

    # ------------------------------------------------------------------
    @property
    def addr_hash(self) -> bytes:
        return addr_mod.pk_to_hash(self.pk)

    @property
    def address(self) -> str:
        return addr_mod.hash_to_address(self.addr_hash, self.hrp)


def derive_key(master_seed: bytes, index: int, hrp: str = "quh") -> WalletKey:
    seed = derive_seed(master_seed, index)
    return WalletKey(index, seed, hrp)


class KeyStore:
    """Derivation cache over the master seed."""

    def __init__(self, master_seed: bytes, hrp: str = "quh"):
        self.master_seed = master_seed
        self.hrp = hrp
        self._cache: List[WalletKey] = []

    def key(self, index: int) -> WalletKey:
        while len(self._cache) <= index:
            i = len(self._cache)
            self._cache.append(derive_key(self.master_seed, i, self.hrp))
        return self._cache[index]

    def addresses(self, count: int) -> List[str]:
        return [self.key(i).address for i in range(count)]

    def find_index(self, address: str) -> int:
        for i in range(len(self._cache)):
            if self._cache[i].address == address:
                return i
        return -1

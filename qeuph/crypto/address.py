"""
Qeuph hashing and address scheme.

Address generation (whitepaper section 3):
  1. public key  <- ML-DSA-87 (2592 bytes)
  2. addr_hash   <- SHA3-512(SHA3-512(public key))     (double hash, 64 bytes)
  3. address     <- bech32m("quh", addr_hash)          ("quh1..." )

Transaction and block identifiers also use double SHA3-512.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from qeuph import constants as C
from qeuph.crypto import bech32m as b32m


def dhash(data: bytes) -> bytes:
    """Double SHA3-512: the Qeuph canonical hash (whitepaper section 2.1)."""
    return hashlib.sha3_512(hashlib.sha3_512(data).digest()).digest()


def sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def pk_to_hash(public_key: bytes) -> bytes:
    """64-byte address hash from an ML-DSA-87 public key."""
    if len(public_key) != C.MLDSA_PK_SIZE:
        raise ValueError(f"public key must be {C.MLDSA_PK_SIZE} bytes")
    return dhash(public_key)


def hash_to_address(addr_hash: bytes, hrp: str = "quh") -> str:
    if len(addr_hash) != C.ADDRESS_HASH_SIZE:
        raise ValueError("address hash must be 64 bytes (double SHA3-512)")
    return b32m.bech32m_encode(hrp, addr_hash, max_length=C.ADDRESS_MAX_LENGTH)


def pk_to_address(public_key: bytes, hrp: str = "quh") -> str:
    return hash_to_address(pk_to_hash(public_key), hrp)


def address_to_hash(address: str, hrp: str = "quh") -> Optional[bytes]:
    """Decode a quh address to its 64-byte hash; None when invalid."""
    if not address or len(address) > C.ADDRESS_MAX_LENGTH:
        return None
    payload = b32m.bech32m_decode(hrp, address, max_length=C.ADDRESS_MAX_LENGTH)
    if payload is None or len(payload) != C.ADDRESS_HASH_SIZE:
        return None
    return payload


def is_valid_address(address: str, hrp: str = "quh") -> bool:
    return address_to_hash(address, hrp) is not None


def hrp_for_network(name: str) -> str:
    return {
        "mainnet": C.ADDRESS_HRP_MAINNET,
        "testnet": C.ADDRESS_HRP_TESTNET,
        "regtest": C.ADDRESS_HRP_REGTEST,
    }[name]

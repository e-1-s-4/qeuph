"""
Unified ML-DSA-87 API for Qeuph.

Backends (first available wins):
  1. `cryptography` >= 45 with ML-DSA support (C, OpenSSL/AWS-LC) - fast path
  2. qeuph.crypto.fips204 - pure-Python reference implementation

Both backends are FIPS 204 conformant and cross-verified: seeded keygen
produces identical public keys, and each backend verifies the other's
signatures.  Signatures and keys are byte-identical in format, so the
blockchain state is fully backend-independent.
"""
from __future__ import annotations

import os
from typing import Optional, Tuple

from qeuph.crypto import fips204

BACKEND = "pure"
_HAS_FAST = False

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _Enc, PrivateFormat as _PrivFmt, PublicFormat as _PubFmt,
        NoEncryption as _NoEnc)
    # probe
    _mldsa.MLDSA87PrivateKey.generate()
    _HAS_FAST = True
    BACKEND = "openssl"
except Exception:  # pragma: no cover - depends on environment
    _mldsa = None

PK_SIZE = fips204.PK_SIZE        # 2592
SK_SIZE = fips204.SK_SIZE        # 4896
SIG_SIZE = fips204.SIG_SIZE      # 4627
SEED_SIZE = 32


def backend_name() -> str:
    return BACKEND


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------
def generate_seed() -> bytes:
    return os.urandom(SEED_SIZE)


import functools

@functools.lru_cache(maxsize=1024)
def keypair_from_seed(seed: bytes) -> Tuple[bytes, bytes]:
    """Deterministic (pk, sk) from a 32-byte seed (FIPS 204 seeded keygen)."""
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be 32 bytes")
    return fips204.keygen_internal(seed)


def generate_keypair() -> Tuple[bytes, bytes, bytes]:
    """Random keypair.  Returns (seed, pk, sk)."""
    seed = generate_seed()
    pk, sk = keypair_from_seed(seed)
    return seed, pk, sk


def pk_from_sk_seed(seed: bytes) -> bytes:
    return keypair_from_seed(seed)[0]


# ---------------------------------------------------------------------------
# Signing / verification
# ---------------------------------------------------------------------------
def sign(sk: bytes, message: bytes, ctx: bytes = b"") -> bytes:
    """Hedged ML-DSA.Sign (FIPS 204 Algorithm 2, default variant)."""
    if len(sk) != SK_SIZE:
        raise ValueError("bad private key length")
    if _HAS_FAST:
        # OpenSSL path needs the seed; recover it via deterministic re-derivation
        # is impossible from sk alone, so use the pure backend for sk blobs.
        # (The fast path is used for seed-based signing below.)
        return fips204.sign(sk, message, ctx, deterministic=False)
    return fips204.sign(sk, message, ctx, deterministic=False)


def sign_with_seed(seed: bytes, message: bytes, ctx: bytes = b"") -> bytes:
    """Hedged signing straight from a 32-byte wallet seed (fast path when available)."""
    if _HAS_FAST:
        key = _mldsa.MLDSA87PrivateKey.from_seed_bytes(seed)
        if ctx:
            return key.sign(message, ctx)
        return key.sign(message)
    sk = keypair_from_seed(seed)[1]
    return fips204.sign(sk, message, ctx, deterministic=False)


def verify(pk: bytes, message: bytes, signature: bytes, ctx: bytes = b"") -> bool:
    """ML-DSA.Verify (FIPS 204 Algorithm 3)."""
    if len(pk) != PK_SIZE or len(signature) != SIG_SIZE:
        return False
    if _HAS_FAST:
        try:
            pub = _mldsa.MLDSA87PublicKey.from_public_bytes(pk)
            pub.verify(signature, message, ctx) if ctx else pub.verify(signature, message)
            return True
        except Exception:
            return False
    return fips204.verify(pk, message, signature, ctx)


def verify_pure(pk: bytes, message: bytes, signature: bytes, ctx: bytes = b"") -> bool:
    """Force the pure-Python reference verifier (used in cross-audit tests)."""
    return fips204.verify(pk, message, signature, ctx)


def deterministic_sign(sk: bytes, message: bytes, ctx: bytes = b"") -> bytes:
    """Deterministic signing (rnd = 0^32) - reproducible signatures."""
    return fips204.sign(sk, message, ctx, deterministic=True)

"""
Proof of work: double SHA3-512 over the serialized block header.

The header's `nonce` field (16 bytes) is the search space.  A block is
valid when the 64-byte block hash, read as a big-endian integer, is
strictly less than the target encoded in the compact `bits` field.

Compact target encoding is BTC-style (32-bit: 8-bit exponent, 24-bit
mantissa) so difficulty arithmetic stays integer-exact.
"""
from __future__ import annotations

import struct

from qeuph import constants as C
from qeuph.crypto.address import dhash

WORK_BITS = 512


# ---------------------------------------------------------------------------
# Compact target (BTC "bits") encoding
# ---------------------------------------------------------------------------
def bits_to_target(bits: int) -> int:
    """Decode compact bits.  Qeuph uses the full unsigned 24-bit mantissa."""
    exponent = bits >> 24
    mantissa = bits & 0x00FFFFFF
    if exponent == 0:
        return mantissa
    if exponent > WORK_BITS // 8:
        raise ValueError("target overflow")
    if mantissa == 0:
        return 0
    if exponent >= 3:
        target = mantissa << (8 * (exponent - 3))
    else:
        target = mantissa >> (8 * (3 - exponent))
    if target >= (1 << WORK_BITS):
        raise ValueError("target overflow")
    return target


def target_to_bits(target: int) -> int:
    """Canonical compact encoding (unsigned mantissa, no sign-bit games).

    t = mantissa << 8*(exponent-3) exactly, so encode/decode roundtrips
    for every valid target.
    """
    if target == 0:
        return 0
    if target >= (1 << WORK_BITS):
        raise ValueError("target overflow")
    exponent = (target.bit_length() + 7) // 8
    if exponent > WORK_BITS // 8:
        raise ValueError("target overflow")
    if exponent >= 3:
        mantissa = target >> (8 * (exponent - 3))
    else:
        mantissa = target << (8 * (3 - exponent))
    return (exponent << 24) | mantissa


def difficulty_from_bits(bits: int) -> float:
    """Difficulty 1.0 reference target: 0x1E0FFFFF-style compact decode."""
    target = bits_to_target(bits)
    if target == 0:
        return float("inf")
    ref = bits_to_target(C.GENESIS_BITS)
    return ref / target


# ---------------------------------------------------------------------------
# PoW check / search
# ---------------------------------------------------------------------------
def header_hash(header_bytes: bytes) -> bytes:
    return dhash(header_bytes)


def check_pow(header_bytes: bytes, bits: int) -> bool:
    target = bits_to_target(bits)
    h = header_hash(header_bytes)
    return int.from_bytes(h, "big") < target


def mine_header(header_bytes_without_nonce: bytes, bits: int,
                start_nonce: int = 0, max_attempts: int = 1 << 34) -> int:
    """Search a 16-byte little-endian nonce appended to the header.

    Returns the winning nonce.  `header_bytes_without_nonce` must end with
    a 16-byte zero placeholder for the nonce field (kept so serialization
    stays fixed-width).
    """
    target = bits_to_target(bits)
    prefix = header_bytes_without_nonce
    for attempt in range(max_attempts):
        nonce = start_nonce + attempt
        blob = prefix[:-16] + nonce.to_bytes(16, "little")
        if int.from_bytes(dhash(blob), "big") < target:
            return nonce
    raise RuntimeError("mine_header: max_attempts exhausted")

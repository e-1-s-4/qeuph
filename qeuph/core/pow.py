"""
Proof of work: double SHA3-512 over the serialized block header.

The header's `nonce` field (16 bytes) is the search space.  A block is
valid when the 64-byte block hash, read as a big-endian integer, is
strictly less than the target encoded in the compact `bits` field.

Compact target encoding is BTC-style (32-bit: 8-bit exponent, 24-bit
mantissa) so difficulty arithmetic stays integer-exact.  Qeuph uses the full
unsigned 24-bit mantissa, which keeps encode/decode round-tripping exact.

Performance note: the mining loop is the hottest code in the node.  The
inner test compares the leading 8 bytes of the digest as a single big-endian
integer against the leading 8 bytes of the target whenever the target is
below 2^504 (every target except the artificial minimum-difficulty regtest
value).  Only when that fast comparison cannot decide does the loop fall
back to a full 512-bit compare, so the result is bit-identical to the
straightforward check while doing a fraction of the work.
"""
from __future__ import annotations

import hashlib

from qeuph import constants as C

WORK_BITS = 512
_DIGEST_SIZE = 64

_sha3_512 = hashlib.sha3_512


# ---------------------------------------------------------------------------
# Compact target (BTC "bits") encoding
# ---------------------------------------------------------------------------
def bits_to_target(bits: int) -> int:
    """Decode compact bits.  Qeuph uses the full unsigned 24-bit mantissa."""
    if bits < 0 or bits > 0xFFFFFFFF:
        raise ValueError("bits out of range")
    exponent = bits >> 24
    mantissa = bits & 0x00FFFFFF
    if exponent == 0:
        if mantissa >= (1 << WORK_BITS):
            raise ValueError("target overflow")
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

    A 24-bit mantissa cannot express an arbitrary 512-bit target, so the
    mantissa is truncated - the encoded target is always <= `target`, i.e.
    the difficulty is never made easier than requested.  This is the same
    lossiness Bitcoin's compact format has, every node computes it
    identically, and the retarget clamp of 4x keeps the relative error far
    below the clamp.  Targets that are exact multiples of 2**(8*(exp-3))
    (which includes the genesis target) round-trip exactly.
    """
    if target == 0:
        return 0
    if target < 0 or target >= (1 << WORK_BITS):
        raise ValueError("target out of range")
    exponent = (target.bit_length() + 7) // 8
    if exponent > WORK_BITS // 8:
        raise ValueError("target overflow")
    if exponent >= 3:
        mantissa = target >> (8 * (exponent - 3))
    else:
        mantissa = target << (8 * (3 - exponent))
    if mantissa > 0x00FFFFFF:
        raise ValueError("mantissa overflow")
    return (exponent << 24) | mantissa


def bits_roundtrip_exact(bits: int) -> bool:
    """True when bits_to_target(bits) is exactly representable."""
    return target_to_bits(bits_to_target(bits)) == bits


def is_valid_bits(bits: int) -> bool:
    """True when `bits` decodes to a target inside the allowed PoW window.

    A compact target is EASIER as it gets numerically larger, so the window is
    [HARDEST_BITS, EASIEST_BITS].
    """
    if bits < C.HARDEST_BITS or bits > C.EASIEST_BITS:
        return False
    try:
        target = bits_to_target(bits)
    except ValueError:
        return False
    return 0 < target < (1 << WORK_BITS)


def difficulty_from_bits(bits: int) -> float:
    """Difficulty 1.0 reference target: the mainnet genesis compact bits."""
    target = bits_to_target(bits)
    if target == 0:
        return float("inf")
    ref = bits_to_target(C.GENESIS_BITS)
    return ref / target


def target_to_difficulty(target: int) -> float:
    ref = bits_to_target(C.GENESIS_BITS)
    return float("inf") if target == 0 else ref / target


# ---------------------------------------------------------------------------
# PoW check / search
# ---------------------------------------------------------------------------
def header_hash(header_bytes: bytes) -> bytes:
    return _sha3_512(_sha3_512(header_bytes).digest()).digest()


def check_pow(header_bytes: bytes, bits: int) -> bool:
    target = bits_to_target(bits)
    return int.from_bytes(header_hash(header_bytes), "big") < target


def check_pow_hash(digest: bytes, bits: int) -> bool:
    """Test an already-computed double SHA3-512 digest against `bits`."""
    target = bits_to_target(bits)
    return int.from_bytes(digest, "big") < target


def mine_header(header_bytes_with_nonce: bytes, bits: int,
                start_nonce: int = 0, max_attempts: int = 1 << 34) -> int:
    """Search the 16-byte little-endian nonce at the end of the header.

    `header_bytes_with_nonce` is a full 168-byte header whose last 16 bytes
    are the (initially zero) nonce field.  Returns the winning nonce.
    """
    target = bits_to_target(bits)
    if target <= 0:
        raise ValueError("zero target")
    for nonce in mine_range(header_bytes_with_nonce, bits, start_nonce,
                            max_attempts):
        return nonce
    raise RuntimeError("mine_header: max_attempts exhausted")


def mine_range(header_bytes_with_nonce: bytes, bits: int,
               start_nonce: int, count: int):
    """Yield every winning nonce found in [start_nonce, start_nonce+count).

    Used by the multi-process miner so each worker owns a disjoint slice of
    the 128-bit nonce space.  The leading 8 bytes of the digest are compared
    against the leading 8 bytes of the target as a plain bytes comparison
    (a memcmp) whenever the target is below 2^504 - which covers every target
    below the artificial regtest minimum.  The 8-byte comparison can only be
    inconclusive when the target's top 64 bits equal the digest's top 64
    bits, and the full 512-bit compare then decides, so the result is
    bit-identical to `check_pow`.
    """
    for nonce, _tried in mine_range_count(header_bytes_with_nonce, bits,
                                          start_nonce, count):
        yield nonce


def mine_range_count(header_bytes_with_nonce: bytes, bits: int,
                     start_nonce: int, count: int):
    """Like mine_range but yields (winning_nonce, hashes_tried) so the miner
    can report an exact hashrate instead of guessing at slice granularity."""
    if len(header_bytes_with_nonce) < 16:
        raise ValueError("header too short")
    target = bits_to_target(bits)
    if target <= 0:
        raise ValueError("zero target")
    prefix = header_bytes_with_nonce[:-16]
    check = _sha3_512
    fast = target < (1 << 504)
    limit8 = (target >> (WORK_BITS - 64)).to_bytes(8, "big") if fast else b""
    to_bytes = int.to_bytes
    for offset in range(count):
        nonce = start_nonce + offset
        blob = prefix + to_bytes(nonce, 16, "little")
        digest = check(check(blob).digest()).digest()
        if fast:
            if digest[:8] < limit8 or \
                    int.from_bytes(digest, "big") < target:
                yield nonce, offset + 1
        elif int.from_bytes(digest, "big") < target:
            yield nonce, offset + 1


def hashes_per_second(bits: int, samples: int = 20000) -> float:
    """Rough single-core PoW rate for the given difficulty (diagnostics)."""
    import os as _os
    import time as _time
    target = bits_to_target(bits)
    fast = target < (1 << 504)
    limit8 = (target >> (WORK_BITS - 64)).to_bytes(8, "big") if fast else b""
    prefix = bytes(152)
    nonce = int.from_bytes(_os.urandom(8), "little")
    t0 = _time.time()
    for i in range(samples):
        digest = _sha3_512(_sha3_512(
            prefix + (nonce + i).to_bytes(16, "little")).digest()).digest()
        if fast and digest[:8] < limit8:
            break
    dt = max(1e-9, _time.time() - t0)
    return samples / dt


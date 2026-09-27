"""
Bech32m reference implementation (BIP-350) used for Qeuph addresses.

Qeuph addresses encode the full 64-byte double-SHA3-512 hash of an ML-DSA-87
public key using Bech32m with the human readable part "quh":

    quh1<103 data characters><6 checksum characters>

The 512-bit payload makes accidental collisions of addresses impossible
even against quantum adversaries, and Bech32m's checksum catches up to
~4 character entry errors (BIP-350 guarantees for lengths <= 1023).
"""
from __future__ import annotations

from typing import List, Optional

# BIP-173/350 character set
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def _polymod(values: List[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> List[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool) -> Optional[List[int]]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def _create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32m_encode(hrp: str, data: bytes, max_length: int = 1023) -> str:
    """Encode 8-bit data as a bech32m string (5-bit convert, padded)."""
    converted = _convertbits(data, 8, 5, True)
    if converted is None:
        raise ValueError("invalid data for bech32m encoding")
    combined = converted + _create_checksum(hrp, converted)
    out = hrp + "1" + "".join(CHARSET[d] for d in combined)
    if len(out) > max_length:
        raise ValueError("bech32m string exceeds the length limit")
    return out


def bech32m_decode(hrp: str, addr: str, max_length: int = 1023) -> Optional[bytes]:
    """Decode a bech32m string; return payload bytes or None if invalid.

    Qeuph deliberately exceeds BIP-350's 90-character limit: the address keeps
    the whole 512-bit double-SHA3-512 digest as payload (113 characters), so
    the limit is raised to `max_length` (C.ADDRESS_MAX_LENGTH) rather than
    truncating the hash.  BIP-350's error-detection guarantee holds for every
    length up to 1023, so nothing is lost.
    """
    if not isinstance(addr, str):
        return None
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return None
    if addr.lower() != addr and addr.upper() != addr:
        return None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > max_length:
        return None
    if addr[:pos] != hrp:
        return None
    data_part = addr[pos + 1:]
    decoded = []
    for c in data_part:
        if c not in CHARSET:
            return None
        decoded.append(CHARSET.index(c))
    data = decoded[:-6]
    if _polymod(_hrp_expand(hrp) + decoded) != BECH32M_CONST:
        return None
    payload = _convertbits(bytes(data), 5, 8, False)
    if payload is None:
        return None
    return bytes(payload)

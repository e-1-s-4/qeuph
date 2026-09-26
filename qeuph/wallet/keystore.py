"""
Encrypted wallet file format (JSON keystore).

Layout (version 1):

    {
      "format": "qeuph-wallet",
      "version": 1,
      "created": <iso8601>,
      "network": "mainnet",
      "crypto": {
        "cipher": "aes-256-gcm" | "xor-sha3-stream",
        "kdf": "pbkdf2-sha3-512",
        "kdf_params": {"n": 60000, "salt": hex},
        "iv": hex, "ciphertext": hex, "tag": hex
      }
    }

When the `cryptography` package (>= 36) is present the seed is sealed with
AES-256-GCM; otherwise a documented SHA3-512 keystream XOR fallback is used
(and clearly flagged).  The KDF is PBKDF2-HMAC-SHA3-512, 60,000 iterations.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets
from typing import Optional

KDF_ITERATIONS = 60_000
FORMAT = "qeuph-wallet"
VERSION = 1

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_AES = True
except Exception:  # pragma: no cover
    _HAS_AES = False


class WalletError(Exception):
    pass


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------
def _kdf(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha3_512", passphrase.encode(), salt, iterations, dklen=32)


# ---------------------------------------------------------------------------
# Stream cipher fallback (documented; use AES path in production)
# ---------------------------------------------------------------------------
def _sha3_keystream(key: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha3_512(key + counter.to_bytes(8, "little")).digest()
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, key: bytes) -> bytes:
    ks = _sha3_keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ---------------------------------------------------------------------------
# Save / load
# ---------------------------------------------------------------------------
def cipher_name() -> str:
    return "aes-256-gcm" if _HAS_AES else "xor-sha3-stream"


def save_wallet(path: str, master_seed: bytes, passphrase: Optional[str],
                network: str = "mainnet", address_count_hint: int = 0):
    if len(master_seed) != 32:
        raise WalletError("master seed must be 32 bytes")
    doc = {
        "format": FORMAT,
        "version": VERSION,
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "network": network,
        "cipher": cipher_name(),
        "address_count_hint": address_count_hint,
    }
    salt = secrets.token_bytes(16)
    doc["kdf"] = {
        "name": "pbkdf2-hmac-sha3-512",
        "iterations": KDF_ITERATIONS,
        "salt": salt.hex(),
    }
    key = _kdf(passphrase or "", salt)
    if _HAS_AES:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, master_seed, b"qeuph-wallet-v1")
        doc["aes"] = {"nonce": nonce.hex(), "ciphertext": ct.hex()}
    else:
        iv = secrets.token_bytes(16)
        ct = _xor(master_seed, hashlib.sha3_512(key + iv).digest())
        mac = hashlib.sha3_512(key + iv + ct).digest()
        doc["fallback"] = {"iv": iv.hex(), "ciphertext": ct.hex(), "mac": mac.hex()}
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def load_wallet(path: str, passphrase: Optional[str]) -> bytes:
    with open(path) as f:
        doc = json.load(f)
    if doc.get("format") != FORMAT:
        raise WalletError("not a qeuph wallet file")
    if doc.get("version") != VERSION:
        raise WalletError(f"unsupported wallet version {doc.get('version')}")
    kdf = doc["kdf"]
    key = _kdf(passphrase or "", bytes.fromhex(kdf["salt"]), kdf["iterations"])
    if "aes" in doc:
        if not _HAS_AES:
            raise WalletError("wallet needs AES-GCM (install 'cryptography')")
        a = doc["aes"]
        try:
            return AESGCM(key).decrypt(bytes.fromhex(a["nonce"]),
                                       bytes.fromhex(a["ciphertext"]), b"qeuph-wallet-v1")
        except Exception:
            raise WalletError("wrong passphrase (or corrupted wallet)")
    fb = doc["fallback"]
    iv = bytes.fromhex(fb["iv"])
    ct = bytes.fromhex(fb["ciphertext"])
    mac = hashlib.sha3_512(key + iv + ct).digest()
    if mac.hex() != fb["mac"]:
        raise WalletError("wrong passphrase (or corrupted wallet)")
    return _xor(ct, hashlib.sha3_512(key + iv).digest())

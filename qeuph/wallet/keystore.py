"""
Encrypted wallet file format (JSON keystore).

Layout (version 2):

    {
      "format": "qeuph-wallet",
      "version": 2,
      "created": "<iso8601 UTC>",
      "network": "mainnet",
      "hrp": "quh",
      "next_index": 0,
      "kdf": {"name": "pbkdf2-hmac-sha3-512", "iterations": 600000,
              "salt": "<hex>"},
      "cipher": "aes-256-gcm" | "sha3-512-keystream-xor",
      "aes":    {"nonce": "<hex>", "ciphertext": "<hex>"}          # AEAD path
      "fallback": {"iv": "<hex>", "ciphertext": "<hex>",
                   "mac": "<hex>"}                                # legacy path
    }

Cipher
    With the `cryptography` package (>= 36) present the 32-byte master seed
    is sealed with AES-256-GCM under a PBKDF2-HMAC-SHA3-512 key, with the
    file-format string bound in as AEAD associated data.  Without it a
    documented SHA3-512 keystream XOR with an encrypt-then-MAC construction
    is used, and the file records which one was applied.

KDF
    PBKDF2-HMAC-SHA3-512.  The default iteration count is 600,000 (version 2);
    version-1 files carry their own (60,000) count in the file and are read
    with it, so old wallets keep opening.  Raise it further with
    `QEUPH_WALLET_KDF_ITERATIONS` for high-value seeds on fast hardware.

Safety
    Files are written through a temp file + atomic rename and chmod 0600.
    A wrong passphrase raises WalletError without leaking which stage failed.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from typing import Optional

KDF_ITERATIONS = 600_000
KDF_ITERATIONS_V1 = 60_000
# Upper bound accepted when READING a wallet file.  PBKDF2-HMAC-SHA3-512 is
# intentionally slow (~0.2 s at 600k), so an unbounded count taken from the
# file would turn every open into an unbounded CPU burn.  Generous enough for
# the next decade of stronger settings, tight enough to stay responsive.
MAX_KDF_ITERATIONS = 10_000_000
FORMAT = "qeuph-wallet"
VERSION = 2
AAD = b"qeuph-wallet-v2"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_AES = True
except Exception:  # pragma: no cover
    _HAS_AES = False


class WalletError(Exception):
    pass


def kdf_iterations() -> int:
    """Iteration count to use when SEALING A NEW wallet file.

    The result is always inside the range `load_wallet` accepts
    (`KDF_ITERATIONS_V1` .. `MAX_KDF_ITERATIONS`), so a file this module
    writes can always be read back by it.  An override below that floor used
    to write a wallet declaring e.g. 1,000 iterations which the loader then
    rejected as "implausible": the seed could not be recovered from its own
    wallet, ever.  Raising the count above the shipped 600,000 still works
    (that is the documented use for a high-value seed on fast hardware).
    """
    override = os.environ.get("QEUPH_WALLET_KDF_ITERATIONS")
    if override:
        try:
            n = int(override)
        except ValueError:
            n = KDF_ITERATIONS
        return max(KDF_ITERATIONS_V1, min(n, MAX_KDF_ITERATIONS))
    return KDF_ITERATIONS


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------
def _kdf(passphrase: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha3_512", passphrase.encode(), salt,
                               iterations, dklen=32)


# ---------------------------------------------------------------------------
# Stream cipher fallback (documented; prefer the AES path)
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
    return "aes-256-gcm" if _HAS_AES else "sha3-512-keystream-xor"


def save_wallet(path: str, master_seed: bytes, passphrase: Optional[str],
                network: str = "mainnet", address_count_hint: int = 0,
                next_index: int = 0, hrp: str = "quh"):
    if len(master_seed) != 32:
        raise WalletError("master seed must be 32 bytes")
    doc = {
        "format": FORMAT,
        "version": VERSION,
        "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "network": network,
        "hrp": hrp,
        "cipher": cipher_name(),
        "address_count_hint": address_count_hint,
        "next_index": int(next_index),
    }
    iterations = kdf_iterations()
    salt = secrets.token_bytes(32)
    doc["kdf"] = {
        "name": "pbkdf2-hmac-sha3-512",
        "iterations": iterations,
        "salt": salt.hex(),
    }
    key = _kdf(passphrase or "", salt, iterations)
    if _HAS_AES:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, master_seed, AAD)
        doc["aes"] = {"nonce": nonce.hex(), "ciphertext": ct.hex()}
    else:
        iv = secrets.token_bytes(32)
        ct = _xor(master_seed, hashlib.sha3_512(key + iv).digest())
        mac = hashlib.sha3_512(key + iv + ct).digest()
        doc["fallback"] = {"iv": iv.hex(), "ciphertext": ct.hex(),
                           "mac": mac.hex()}
    _write_atomic(path, doc)


def _write_atomic(path: str, doc: dict):
    d = os.path.dirname(os.path.abspath(path))
    if d:
        # 0700: the directory holds the wallet file and its temp name, and
        # neither should be world-readable.
        os.makedirs(d, mode=0o700, exist_ok=True)
    # mkstemp creates the file with O_EXCL and a random name, so it can
    # neither collide with a concurrent writer in the same process nor be
    # pre-created by a local attacker pointing a symlink at another file.
    fd, tmp = tempfile.mkstemp(dir=d or ".", prefix=os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        # fsync the directory so the rename itself is durable; without it a
        # crash can lose the file that was just written.
        if d:
            try:
                dfd = os.open(d, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                # not fatal: not every filesystem allows opening a directory
                pass
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_wallet(path: str, passphrase: Optional[str]) -> bytes:
    try:
        with open(path) as f:
            doc = json.load(f)
    except FileNotFoundError:
        raise WalletError(f"wallet file not found: {path}")
    except json.JSONDecodeError as e:
        raise WalletError(f"wallet file is not valid JSON: {e}")
    if doc.get("format") != FORMAT:
        raise WalletError("not a qeuph wallet file")
    version = doc.get("version")
    if version not in (1, 2):
        raise WalletError(f"unsupported wallet version {version}")
    try:
        kdf = doc["kdf"]
        # The iteration count comes from the file, so it is attacker- or
        # corruption-controlled input on the open path.  PBKDF2 is
        # deliberately slow: an implausible value turns every `Wallet.open`
        # (and therefore every web-UI wallet request) into a hang.  Refuse
        # anything outside the range a real file can legitimately hold.
        try:
            iterations = int(kdf["iterations"])
        except (KeyError, TypeError, ValueError) as exc:
            raise WalletError("wallet file has no usable kdf iteration count") \
                from exc
        if not (KDF_ITERATIONS_V1 <= iterations <= MAX_KDF_ITERATIONS):
            raise WalletError(
                f"implausible kdf iteration count {iterations} "
                f"(expected {KDF_ITERATIONS_V1}..{MAX_KDF_ITERATIONS})")
        key = _kdf(passphrase or "", bytes.fromhex(kdf["salt"]),
                   iterations)
    except (KeyError, ValueError) as e:
        raise WalletError(f"wallet file is missing key material: {e}")
    if "aes" in doc:
        if not _HAS_AES:
            raise WalletError("this wallet needs AES-GCM; install 'cryptography'")
        a = doc["aes"]
        try:
            return AESGCM(key).decrypt(bytes.fromhex(a["nonce"]),
                                       bytes.fromhex(a["ciphertext"]), AAD)
        except Exception:
            raise WalletError("wrong passphrase (or corrupted wallet)")
    fb = doc.get("fallback")
    if not fb or not isinstance(fb, dict):
        raise WalletError("wallet file has no ciphertext")
    try:
        iv = bytes.fromhex(fb["iv"])
        ct = bytes.fromhex(fb["ciphertext"])
        stored_mac = bytes.fromhex(fb["mac"])
    except (KeyError, TypeError, ValueError) as exc:
        raise WalletError(f"wallet file is corrupted: {exc}") from exc
    mac = hashlib.sha3_512(key + iv + ct).digest()
    # compare_digest raises TypeError on mismatched types, so normalise
    # first: a tampered file must fail authentication, not crash the loader
    if not hmac.compare_digest(mac, stored_mac):
        raise WalletError("wrong passphrase (or corrupted wallet)")
    seed = _xor(ct, hashlib.sha3_512(key + iv).digest())
    if len(seed) != 32:
        raise WalletError("wallet file is corrupted")
    return seed


def load_wallet_doc(path: str) -> dict:
    """Read the wallet JSON document (metadata only, no decryption)."""
    try:
        with open(path) as f:
            doc = json.load(f)
    except FileNotFoundError:
        raise WalletError(f"wallet file not found: {path}")
    except json.JSONDecodeError as e:
        raise WalletError(f"wallet file is not valid JSON: {e}")
    if doc.get("format") != FORMAT:
        raise WalletError("not a qeuph wallet file")
    return doc


def reencrypt(path: str, old_passphrase: Optional[str],
              new_passphrase: Optional[str]) -> None:
    """Change the passphrase of an existing wallet file in place."""
    seed = load_wallet(path, old_passphrase)
    doc = load_wallet_doc(path)
    save_wallet(path, seed, new_passphrase,
                network=doc.get("network", "mainnet"),
                address_count_hint=int(doc.get("address_count_hint", 0)),
                next_index=int(doc.get("next_index", 0)),
                hrp=doc.get("hrp", "quh"))

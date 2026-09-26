"""
High-level wallet: balance lookup, transaction construction, signing and
broadcast via the node RPC (or offline against a chain copy).

Ported from QRL's core/Wallet.py + wallet tooling to the seed-derived
ML-DSA-87 model.

Privacy (whitepaper 6.1): change outputs default to a FRESH derived
address rather than the paying address, and the wallet persists a
next-address index so a restart never re-issues an already-used address.
"""
from __future__ import annotations

import json
import urllib.request
from typing import List, Optional, Tuple

from qeuph import constants as C
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.crypto import address as addr_mod
from qeuph.wallet import keystore
from qeuph.wallet.keystore import WalletError
from qeuph.wallet.keys import KeyStore, derive_key
from qeuph.wallet import mnemonic as mnemonic_mod


class Wallet:
    def __init__(self, master_seed: bytes, hrp: str = "quh", network: str = "mainnet",
                 path: Optional[str] = None, passphrase: Optional[str] = None,
                 next_index: int = 0):
        self.master_seed = master_seed
        self.hrp = hrp
        self.network_name = network
        self.keys = KeyStore(master_seed, hrp)
        self.path = path
        self.passphrase = passphrase
        self.next_index = max(0, int(next_index))

    # ------------------------------------------------------------------
    @classmethod
    def create(cls, hrp: str = "quh", network: str = "mainnet") -> "Wallet":
        import os
        return cls(os.urandom(32), hrp, network)

    @classmethod
    def from_mnemonic(cls, phrase: str, hrp: str = "quh",
                      network: str = "mainnet") -> "Wallet":
        seed = mnemonic_mod.mnemonic_to_entropy(phrase)
        return cls(seed, hrp, network)

    def to_mnemonic(self) -> str:
        return mnemonic_mod.entropy_to_mnemonic(self.master_seed)

    # ------------------------------------------------------------------
    @classmethod
    def open(cls, path: str, passphrase: Optional[str] = None,
             hrp: str = "quh", network: str = "mainnet") -> "Wallet":
        seed = keystore.load_wallet(path, passphrase)
        try:
            doc = keystore.load_wallet_doc(path)
            next_index = int(doc.get("next_index", 0))
        except Exception:
            next_index = 0
        return cls(seed, hrp, network, path=path, passphrase=passphrase,
                   next_index=next_index)

    def save(self, path: Optional[str] = None, passphrase: Optional[str] = None,
             address_count_hint: int = 0):
        path = path or self.path or "wallet.json"
        passphrase = passphrase if passphrase is not None else self.passphrase
        keystore.save_wallet(path, self.master_seed, passphrase,
                             self.network_name, address_count_hint,
                             next_index=self.next_index)
        self.path = path

    # ------------------------------------------------------------------
    # address management
    # ------------------------------------------------------------------
    def new_address(self) -> str:
        """Derive the next unused address and persist the index so restarts
        never re-issue it (whitepaper 6.1 rotation discipline)."""
        addr = self.address_at(self.next_index)
        self.next_index += 1
        if self.path is not None:
            try:
                self.save()
            except Exception:
                pass
        return addr

    def address_at(self, index: int) -> str:
        return self.keys.key(index).address

    def find_index(self, address: str, scan: int = 64) -> int:
        """Index of a derived address (scans the next `scan` indices)."""
        for i in range(scan):
            if self.address_at(i) == address:
                return i
        return -1

    # ------------------------------------------------------------------
    # UTXO lookups (via RPC when available)
    # ------------------------------------------------------------------
    def fetch_utxos(self, address: str, rpc_url: Optional[str],
                    matured_only: bool = True) -> List[Tuple[bytes, int, int]]:
        """[(txid, index, value)] for an address."""
        if rpc_url:
            res = _rpc(rpc_url, "listutxos", {"address": address, "matured_only": matured_only})
            return [(bytes.fromhex(u["txid"]), u["index"], u["value"])
                    for u in res.get("utxos", [])]
        raise WalletError("no rpc_url provided for UTXO lookup")

    def fetch_nonce(self, address: str, rpc_url: Optional[str]) -> int:
        if rpc_url:
            res = _rpc(rpc_url, "getnonce", {"address": address})
            return int(res.get("nonce", 0))
        return 0

    def balance(self, rpc_url: Optional[str], index: int = 0,
                confirmations_required: Optional[int] = None) -> int:
        addr = self.address_at(index)
        res = _rpc(rpc_url, "getbalance", {"address": addr})
        return int(res.get("balance", 0))

    # ------------------------------------------------------------------
    # transaction building
    # ------------------------------------------------------------------
    def build_transaction(self, sender_index: int, recipients: List[Tuple[str, int]],
                          fee: int = 1_000_000, rpc_url: Optional[str] = None,
                          maturity_height: Optional[int] = None,
                          fresh_change: bool = True,
                          lock_time: int = 0) -> Transaction:
        """Create + sign a transaction spending matured UTXOs of address
        `sender_index`, paying `recipients` [(address, quphi)].

        With fresh_change=True (default, whitepaper 6.1) the change output
        pays a brand-new derived address; otherwise it returns to the
        sender (legacy behaviour)."""
        sender_addr = self.address_at(sender_index)
        sender_hash = addr_mod.address_to_hash(sender_addr, self.hrp)
        if sender_hash is None:
            raise WalletError("bad sender address (hrp mismatch?)")
        utxos = self.fetch_utxos(sender_addr, rpc_url, matured_only=True)
        total = sum(v for _, _, v in utxos)
        pay = sum(v for _, v in recipients)
        if total < pay + fee:
            raise WalletError(f"insufficient funds: {total} < {pay + fee}")
        nonce = self.fetch_nonce(sender_addr, rpc_url) + 1
        # pick UTXOs (largest first)
        picked = []
        acc = 0
        for txid, idx, value in sorted(utxos, key=lambda u: -u[2]):
            picked.append((txid, idx, value))
            acc += value
            if acc >= pay + fee:
                break
        change = acc - pay - fee
        outputs = []
        for addr_str, value in recipients:
            h = addr_mod.address_to_hash(addr_str, self.hrp)
            if h is None or len(h) != 64:
                raise WalletError(f"invalid recipient address: {addr_str}")
            outputs.append(TxOut(value, h))
        if change > 0:
            if fresh_change:
                # fresh change index: never the sender and never re-used
                change_index = max(self.next_index, sender_index + 1)
                change_addr = self.address_at(change_index)
                change_hash = addr_mod.address_to_hash(change_addr, self.hrp)
                if change_hash is None:
                    raise WalletError("derived change address failed to decode")
                outputs.append(TxOut(change, change_hash))
                self.next_index = change_index + 1
                if self.path is not None:
                    try:
                        self.save()
                    except Exception:
                        pass
            else:
                outputs.append(TxOut(change, sender_hash))
        key = self.keys.key(sender_index)
        inputs = [TxIn(txid, idx, nonce) for txid, idx, _ in picked]
        tx = Transaction(inputs, outputs, lock_time=lock_time)
        tx.sign([key.seed] * len(inputs))
        return tx

    def send_transaction(self, tx: Transaction, rpc_url: str) -> str:
        res = _rpc(rpc_url, "sendtransaction", {"tx_hex": tx.serialize().hex()})
        if not res.get("accepted"):
            raise WalletError(f"node rejected transaction: {res.get('reason')}")
        return tx.txid().hex()

    # ------------------------------------------------------------------
    def info(self, count: int = 5) -> dict:
        return {
            "network": self.network_name,
            "addresses": [self.address_at(i) for i in range(count)],
            "next_index": self.next_index,
        }


# ---------------------------------------------------------------------------
def _rpc(rpc_url: str, method: str, params: dict) -> dict:
    import urllib.error
    payload = json.dumps({"jsonrpc": "2.0", "id": 1,
                          "method": method, "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            doc = json.loads(resp.read())
    except urllib.error.HTTPError as err:
        try:
            doc = json.loads(err.read().decode())
        except Exception:
            raise WalletError(f"HTTP {err.code}: {err.reason}")
    if "error" in doc and doc["error"]:
        raise WalletError(f"rpc error: {doc['error']}")
    return doc.get("result", {})

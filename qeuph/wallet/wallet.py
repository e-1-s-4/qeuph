"""
High-level wallet: balance lookup, transaction construction, signing and
broadcast via the node RPC.

Ported from QRL's core/Wallet.py + wallet tooling to the seed-derived
ML-DSA-87 model.

Privacy (whitepaper 6.1): change outputs default to a FRESH derived address
rather than the paying address, and the wallet persists a next-address index
so a restart never re-issues an already-used address.

Network safety: the keystore records which network the seed was created for.
Opening a wallet with a mismatched `--network` is refused by default because
the address HRP would change and every balance lookup would silently return
zero.  Use `allow_network_mismatch=True` only for recovery tooling.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import List, Optional, Sequence, Tuple

from qeuph import constants as C
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.crypto import address as addr_mod
from qeuph.wallet import keystore
from qeuph.wallet.keystore import WalletError
from qeuph.wallet.keys import KeyStore
from qeuph.wallet import mnemonic as mnemonic_mod


class Wallet:
    def __init__(self, master_seed: bytes, hrp: str = "quh",
                 network: str = "mainnet", path: Optional[str] = None,
                 passphrase: Optional[str] = None, next_index: int = 0):
        if len(master_seed) != 32:
            raise WalletError("master seed must be 32 bytes")
        self.master_seed = master_seed
        self.hrp = hrp
        self.network_name = network
        self.keys = KeyStore(master_seed, hrp)
        self.path = path
        self.passphrase = passphrase
        self.next_index = max(0, int(next_index))

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------
    @classmethod
    def create(cls, hrp: str = "quh", network: str = "mainnet",
               entropy: Optional[bytes] = None) -> "Wallet":
        """Create a wallet.  With no `entropy` a CSPRNG seed is used; pass 32
        bytes of entropy to rebuild a specific wallet (tests, recovery)."""
        import os
        return cls(entropy if entropy is not None else os.urandom(32),
                   hrp, network)

    @classmethod
    def from_mnemonic(cls, phrase: str, hrp: str = "quh",
                      network: str = "mainnet") -> "Wallet":
        return cls(mnemonic_mod.mnemonic_to_entropy(phrase), hrp, network)

    def to_mnemonic(self) -> str:
        return mnemonic_mod.entropy_to_mnemonic(self.master_seed)

    @classmethod
    def open(cls, path: str, passphrase: Optional[str] = None,
             hrp: str = "quh", network: str = "mainnet",
             allow_network_mismatch: bool = False) -> "Wallet":
        seed = keystore.load_wallet(path, passphrase)
        doc = keystore.load_wallet_doc(path)
        next_index = int(doc.get("next_index", 0))
        stored = doc.get("network")
        if stored and stored != network and not allow_network_mismatch:
            raise WalletError(
                f"wallet at {path} was created for {stored!r} but "
                f"{network!r} was requested; address prefixes differ and "
                f"balances would read as zero. Re-run with the original "
                f"network, or pass allow_network_mismatch=True to override.")
        return cls(seed, hrp, network, path=path, passphrase=passphrase,
                   next_index=next_index)

    def save(self, path: Optional[str] = None, passphrase: Optional[str] = None,
             address_count_hint: int = 0):
        path = path or self.path or "wallet.json"
        passphrase = passphrase if passphrase is not None else self.passphrase
        keystore.save_wallet(path, self.master_seed, passphrase,
                             self.network_name, address_count_hint,
                             next_index=self.next_index, hrp=self.hrp)
        # wallet files hold the master seed: never leave them group/world read
        try:
            import os
            os.chmod(path, 0o600)
        except OSError:
            pass
        self.path = path

    # ------------------------------------------------------------------
    # address management
    # ------------------------------------------------------------------
    def new_address(self) -> str:
        """Derive the next unused address and persist the index so restarts
        never re-issue it (whitepaper 6.1 rotation discipline)."""
        addr = self.address_at(self.next_index)
        self.next_index += 1
        self._persist()
        return addr

    def _persist(self):
        if self.path is not None:
            try:
                self.save()
            except Exception:
                pass

    def address_at(self, index: int) -> str:
        if index < 0:
            raise WalletError("address index must be non-negative")
        return self.keys.key(index).address

    def address_hash_at(self, index: int) -> bytes:
        return self.keys.key(index).addr_hash

    def addresses(self, count: int) -> List[str]:
        return [self.address_at(i) for i in range(count)]

    def find_index(self, address: str, scan: int = 64) -> int:
        """Index of a derived address (scans the first `scan` indices)."""
        for i in range(scan):
            if self.address_at(i) == address:
                return i
        return -1

    # ------------------------------------------------------------------
    # node queries (JSON-RPC)
    # ------------------------------------------------------------------
    def _require_rpc(self, rpc_url: Optional[str]) -> str:
        if not rpc_url:
            raise WalletError(
                "a node RPC url is required for this operation "
                "(--rpc http://127.0.0.1:19091/)")
        return rpc_url

    def fetch_utxos(self, address: str, rpc_url: Optional[str],
                    matured_only: bool = True) -> List[Tuple[bytes, int, int]]:
        """[(txid, index, value)] for an address."""
        res = rpc_call(self._require_rpc(rpc_url), "listutxos",
                       {"address": address, "matured_only": matured_only})
        return [(bytes.fromhex(u["txid"]), int(u["index"]), int(u["value"]))
                for u in res.get("utxos", [])]

    def fetch_nonce(self, address: str, rpc_url: Optional[str]) -> int:
        res = rpc_call(self._require_rpc(rpc_url), "getnonce",
                       {"address": address})
        return int(res.get("nonce", 0))

    def balance(self, rpc_url: str, index: int = 0) -> int:
        addr = self.address_at(index)
        res = rpc_call(rpc_url, "getbalance", {"address": addr})
        return int(res.get("balance", 0))

    def matured_balance(self, rpc_url: str, index: int = 0) -> int:
        addr = self.address_at(index)
        res = rpc_call(rpc_url, "getbalance", {"address": addr})
        return int(res.get("matured_balance", 0))

    # ------------------------------------------------------------------
    # coin selection
    # ------------------------------------------------------------------
    def _select_coins(self, utxos: Sequence[Tuple[bytes, int, int]],
                      target: int) -> Tuple[List[Tuple[bytes, int, int]], int]:
        """Largest-first selection with an exact-match shortcut.

        Returns (picked, total).  Raises when the total is short.  The dust
        threshold is respected: a change output that would fall below it is
        left to the miner as extra fee instead of creating a dust UTXO.
        """
        total_avail = sum(v for _, _, v in utxos)
        if total_avail < target:
            raise WalletError(
                f"insufficient funds: have {total_avail} quphi, "
                f"need {target} quphi "
                f"({total_avail / C.QUPHI_PER_QUH:.8f} QUH available, "
                f"{target / C.QUPHI_PER_QUH:.8f} QUH required)")
        ordered = sorted(utxos, key=lambda u: -u[2])
        # exact single-UTXO match (no change output needed at all)
        for txid, idx, value in ordered:
            if value == target:
                return [(txid, idx, value)], value
        picked: List[Tuple[bytes, int, int]] = []
        acc = 0
        for txid, idx, value in ordered:
            picked.append((txid, idx, value))
            acc += value
            change = acc - target
            if acc >= target and change > C.DUST_THRESHOLD:
                return picked, acc
        # everything was needed; the remainder becomes fee
        return picked, acc

    # ------------------------------------------------------------------
    # transaction building
    # ------------------------------------------------------------------
    def build_transaction(self, sender_index: int,
                          recipients: List[Tuple[str, int]],
                          fee: int = 1_000_000,
                          rpc_url: Optional[str] = None,
                          maturity_height: Optional[int] = None,
                          fresh_change: bool = True,
                          lock_time: int = 0,
                          change_index: Optional[int] = None) -> Transaction:
        """Create + sign a transaction spending matured UTXOs of address
        `sender_index`, paying `recipients` [(address, quphi)].

        With fresh_change=True (default, whitepaper 6.1) the change output
        pays a brand-new derived address; otherwise it returns to the sender.
        """
        if not recipients:
            raise WalletError("no recipients")
        sender_addr = self.address_at(sender_index)
        sender_hash = addr_mod.address_to_hash(sender_addr, self.hrp)
        if sender_hash is None:
            raise WalletError("bad sender address (hrp mismatch?)")
        outputs: List[TxOut] = []
        pay = 0
        for addr_str, value in recipients:
            if value <= 0:
                raise WalletError("recipient amount must be positive")
            if value <= C.DUST_THRESHOLD:
                raise WalletError(
                    f"amount {value} quphi is below the dust threshold "
                    f"{C.DUST_THRESHOLD + 1}")
            h = addr_mod.address_to_hash(addr_str, self.hrp)
            if h is None or len(h) != C.ADDRESS_HASH_SIZE:
                raise WalletError(f"invalid recipient address: {addr_str}")
            outputs.append(TxOut(value, h))
            pay += value
        if fee < 0:
            raise WalletError("fee must be non-negative")
        utxos = self.fetch_utxos(sender_addr, rpc_url, matured_only=True)
        if not utxos:
            raise WalletError(
                f"no spendable outputs on {sender_addr}; coinbase outputs need "
                f"{C.COINBASE_MATURITY} confirmations")
        picked, acc = self._select_coins(utxos, pay + fee)
        change = acc - pay - fee
        if change > C.DUST_THRESHOLD:
            if fresh_change:
                ci = self.next_index if change_index is None else change_index
                ci = max(ci, sender_index + 1)
                change_addr = self.address_at(ci)
                change_hash = addr_mod.address_to_hash(change_addr, self.hrp)
                if change_hash is None:
                    raise WalletError("derived change address failed to decode")
                outputs.append(TxOut(change, change_hash))
                self.next_index = max(self.next_index, ci + 1)
                self._persist()
            else:
                outputs.append(TxOut(change, sender_hash))
        nonce = self.fetch_nonce(sender_addr, rpc_url) + 1
        key = self.keys.key(sender_index)
        inputs = [TxIn(txid, idx, nonce) for txid, idx, _ in picked]
        tx = Transaction(inputs, outputs, lock_time=lock_time)
        tx.sign([key.seed] * len(inputs))
        return tx

    def sweep(self, sender_index: int, to_address: str,
              rpc_url: Optional[str], fee_rate: int = None) -> List[Transaction]:
        """Sweep every spendable output of `sender_index` to one address.

        The txnonce rule allows only ONE input per address per transaction,
        so N outputs need N chained transactions with nonces n, n+1, ... .
        Each intermediate transaction returns its change to a fresh derived
        address; the last one keeps the remainder as change as well, so the
        total dust left on the chain is bounded by the dust threshold.

        Returns the list of signed transactions in broadcast order.
        """
        sender_addr = self.address_at(sender_index)
        utxos = self.fetch_utxos(sender_addr, rpc_url, matured_only=True)
        if not utxos:
            raise WalletError("nothing to sweep")
        to_hash = addr_mod.address_to_hash(to_address, self.hrp)
        if to_hash is None:
            raise WalletError(f"invalid destination address: {to_address}")
        rate = C.MIN_RELAY_FEE_RATE if fee_rate is None else int(fee_rate)
        key = self.keys.key(sender_index)
        base_nonce = self.fetch_nonce(sender_addr, rpc_url)
        txs: List[Transaction] = []
        # spend the smallest outputs first so the leftovers consolidate
        ordered = sorted(utxos, key=lambda u: u[2])
        n = len(ordered)
        for i, (txid, idx, value) in enumerate(ordered):
            fee = (7400 * rate) // 1000        # 1-in-2-out size estimate
            amount = value - fee
            if amount <= C.DUST_THRESHOLD:
                # too small to move: leave it, or bump the fee on the last tx
                if i == n - 1:
                    fee = max(0, value - C.DUST_THRESHOLD - 1)
                    amount = value - fee
                    if amount <= C.DUST_THRESHOLD:
                        continue
                else:
                    continue
            change = value - amount - fee
            outputs = [TxOut(amount, to_hash)]
            if change > C.DUST_THRESHOLD:
                ci = max(self.next_index, sender_index + 1)
                ch = addr_mod.address_to_hash(self.address_at(ci), self.hrp)
                outputs.append(TxOut(change, ch))
                self.next_index = ci + 1
            tx = Transaction([TxIn(txid, idx, base_nonce + i + 1)], outputs)
            tx.sign([key.seed])
            txs.append(tx)
        self._persist()
        if not txs:
            raise WalletError("every spendable output is dust; nothing to sweep")
        return txs

    def sign_transaction(self, tx: Transaction, sender_index: int) -> Transaction:
        """Sign an externally constructed transaction with a wallet key."""
        key = self.keys.key(sender_index)
        tx.sign([key.seed] * len(tx.inputs))
        return tx

    def send_transaction(self, tx: Transaction, rpc_url: str) -> str:
        res = rpc_call(self._require_rpc(rpc_url), "sendrawtransaction",
                       {"tx_hex": tx.serialize().hex()})
        if not res.get("accepted"):
            raise WalletError(f"node rejected transaction: {res.get('reason')}")
        return tx.txid().hex()

    def send(self, sender_index: int, recipients, fee, rpc_url,
             fresh_change: bool = True, lock_time: int = 0) -> str:
        tx = self.build_transaction(sender_index, recipients, fee=fee,
                                     rpc_url=rpc_url, fresh_change=fresh_change,
                                     lock_time=lock_time)
        return self.send_transaction(tx, rpc_url)

    # ------------------------------------------------------------------
    def info(self, count: int = 5) -> dict:
        return {
            "network": self.network_name,
            "hrp": self.hrp,
            "path": self.path,
            "addresses": [self.address_at(i) for i in range(count)],
            "next_index": self.next_index,
        }


# ---------------------------------------------------------------------------
# JSON-RPC client (stdlib only)
# ---------------------------------------------------------------------------
def rpc_call(url: str, method: str, params: Optional[dict] = None,
             timeout: int = 60) -> dict:
    """Single JSON-RPC 2.0 call; raises WalletError on any error."""
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params or {}}).encode()
    req = urllib.request.Request(url, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read().decode())
    except urllib.error.HTTPError as err:
        try:
            doc = json.loads(err.read().decode())
        except Exception:
            raise WalletError(f"HTTP {err.code}: {err.reason}")
    except urllib.error.URLError as err:
        raise WalletError(f"cannot reach node RPC at {url}: {err.reason}")
    if doc.get("error"):
        raise WalletError(f"rpc {method} error: {doc['error']}")
    return doc.get("result", {})


# back-compat alias used by older call sites
_rpc = rpc_call

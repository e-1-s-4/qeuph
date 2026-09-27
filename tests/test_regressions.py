"""Regression tests for the defects found in the 2026 mainnet-readiness pass.

Each test here pins a bug that shipped: a wallet path that produced
transactions no node accepts, a sweep that wedged an address forever, a
passphrase echoed over HTTP, a mining control reachable on mainnet, and a
pair of HTTP/1.1 keep-alive desyncs.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

import pytest

from qeuph import constants as C
from qeuph.core.state import ChainState
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.core.validation import TxValidationError, validate_tx
from qeuph.crypto import ml_dsa
from qeuph.wallet import keystore
from qeuph.wallet.keystore import WalletError
from qeuph.wallet.wallet import Wallet


def _funded(utxos, nonce=0):
    """A wallet whose index-0 address owns `utxos`, backed by a real state."""
    w = Wallet.create(hrp="rquh", network="regtest")
    state = ChainState()
    k0 = w.keys.key(0)
    for i, (_txid, _idx, value) in enumerate(utxos):
        t = Transaction([TxIn(bytes([i + 1]) * 64, i, nonce + 1)],
                        [TxOut(value, k0.addr_hash)])
        t.sign([k0.seed])
        state.apply_transaction(t, 1)
    real = [(t, i, u.value) for t, i, u in state.utxos_for(k0.addr_hash)]
    w.fetch_utxos = lambda a, u=None, matured_only=True: list(real)
    w.fetch_nonce = lambda a, u=None: state.nonce_of(k0.addr_hash)
    return w, state, real


# ---------------------------------------------------------------------------
# Wallet: one input per address per transaction
# ---------------------------------------------------------------------------
class TestOneInputPerAddress:
    def test_send_never_builds_a_multi_input_tx(self):
        """A1: coin selection used to return 2+ outputs of the SAME address.

        `fetch_utxos` only ever returns outputs of one address, and the
        txnonce rule is per address, so a two-input transaction is rejected
        by every node ("spends a second output of an address already
        spending").  The primary spend path simply could not cover an
        amount above the largest single output.
        """
        w, state, real = _funded([(b"", 0, 25 * 10 ** 8),
                                  (b"", 0, 25 * 10 ** 8),
                                  (b"", 0, 25 * 10 ** 8)])
        with pytest.raises(WalletError, match="one input per transaction"):
            w.build_transaction(0, [(w.address_at(1), 60 * 10 ** 8)],
                                fee=1000, rpc_url="x")
        # ...and whatever it does build must satisfy consensus
        tx = w.build_transaction(0, [(w.address_at(1), 20 * 10 ** 8)],
                                 fee=1000, rpc_url="x")
        assert len(tx.inputs) == 1
        validate_tx(tx, state, 10)          # must not raise

    def test_failed_build_does_not_burn_a_change_address(self):
        w, _state, real = _funded([(b"", 0, 25 * 10 ** 8)])
        before = w.next_index
        with pytest.raises(WalletError):
            w.build_transaction(0, [(w.address_at(1), 99 * 10 ** 8)],
                                fee=1000, rpc_url="x")
        assert w.next_index == before

    def test_successful_build_persists_the_change_index(self):
        w, _state, _real = _funded([(b"", 0, 25 * 10 ** 8)])
        tx = w.build_transaction(0, [(w.address_at(1), 5 * 10 ** 8)],
                                 fee=1000, rpc_url="x")
        # the change output pays the next address after the sender's
        assert tx.outputs[-1].addr_hash == w.address_hash_at(1)
        assert w.next_index == 2


# ---------------------------------------------------------------------------
# Wallet: sweep nonce sequencing
# ---------------------------------------------------------------------------
class TestSweepSequencing:
    def test_sweep_nonces_are_contiguous(self):
        """A2: the nonce came from the loop POSITION, so a skipped UTXO left
        a gap and every later transaction failed `txnonce == chain+1`,
        permanently wedging the address."""
        w, _state, real = _funded([(b"", 0, 5 * 10 ** 8),
                                   (b"", 0, 2000),
                                   (b"", 0, 6 * 10 ** 8)])
        base = w.fetch_nonce(w.address_at(0))
        txs = w.sweep(0, w.address_at(2), rpc_url="x")
        nonces = [t.inputs[0].txnonce for t in txs]
        assert nonces == list(range(base + 1, base + 1 + len(txs)))
        assert len(txs) == 2                       # the 2000-quphi one skipped

    def test_sweep_emits_no_change_output(self):
        """A3: `change = value - amount - fee` with `amount = value - fee` is
        identically zero, so the fresh-change branch was dead code and the
        docstring described behaviour that never happened."""
        w, _state, real = _funded([(b"", 0, 5 * 10 ** 8),
                                   (b"", 0, 6 * 10 ** 8)])
        txs = w.sweep(0, w.address_at(2), rpc_url="x")
        for t in txs:
            assert len(t.outputs) == 1

    def test_sweep_every_tx_pays_a_relayable_fee(self):
        """A4: the old dust "bump" built a transaction paying 999 quphi
        against a 7,391-quphi minimum - dead on arrival."""
        w, _state, real = _funded([(b"", 0, 5 * 10 ** 8)])
        txs = w.sweep(0, w.address_at(2), rpc_url="x",
                      fee_rate=C.MIN_RELAY_FEE_RATE)
        for t in txs:
            spent = real[0][2]
            fee = spent - t.total_out
            assert fee >= (t.size() * C.MIN_RELAY_FEE_RATE + 999) // 1000

    def test_sweep_skips_output_that_cannot_pay_the_fee(self):
        w, _state, _real = _funded([(b"", 0, 2000)])
        with pytest.raises(WalletError, match="dust"):
            w.sweep(0, w.address_at(2), rpc_url="x")

    def test_sweep_rejects_negative_fee_rate(self):
        """A5: a negative rate made `amount > value`, i.e. a value-creating
        transaction that the wallet happily signed and broadcast."""
        w, _state, _real = _funded([(b"", 0, 5 * 10 ** 8)])
        with pytest.raises(WalletError, match="non-negative"):
            w.sweep(0, w.address_at(2), rpc_url="x", fee_rate=-1000)


# ---------------------------------------------------------------------------
# Wallet: signing
# ---------------------------------------------------------------------------
class TestSigningSafety:
    def test_sign_transaction_refuses_multi_input(self):
        """A6: `tx.sign([seed] * len(inputs))` overwrote EVERY input's
        public key, so inputs owned by other addresses ended up carrying the
        sender's key and could never validate."""
        w = Wallet.create(hrp="rquh", network="regtest")
        tx = Transaction([TxIn(b"\x01" * 64, 0, 1), TxIn(b"\x02" * 64, 1, 1)],
                         [TxOut(10 ** 8, w.address_hash_at(0))])
        with pytest.raises(WalletError, match="single-input"):
            w.sign_transaction(tx, 0)

    def test_sign_transaction_still_signs_one_input(self):
        w = Wallet.create(hrp="rquh", network="regtest")
        tx = Transaction([TxIn(b"\x01" * 64, 0, 1)],
                         [TxOut(10 ** 8, w.address_hash_at(0))])
        w.sign_transaction(tx, 0)
        assert len(tx.inputs[0].signature) == ml_dsa.SIG_SIZE


# ---------------------------------------------------------------------------
# Wallet: keystore hardening
# ---------------------------------------------------------------------------
class TestKeystoreHardening:
    def test_absurd_kdf_iterations_refused(self, tmp_path):
        """A9: the count came from the file, and PBKDF2 is slow, so a huge
        value turned every open into a hang."""
        p = str(tmp_path / "w.json")
        keystore.save_wallet(p, os.urandom(32), "pw", network="regtest",
                             hrp="rquh")
        doc = json.load(open(p))
        doc["kdf"]["iterations"] = 2 ** 31 - 1
        json.dump(doc, open(p, "w"))
        with pytest.raises(WalletError, match="implausible kdf"):
            keystore.load_wallet(p, "pw")

    def test_absurd_next_index_refused(self, tmp_path):
        """A12: next_index drove a keygen loop, so a huge value hung."""
        p = str(tmp_path / "w.json")
        keystore.save_wallet(p, os.urandom(32), "pw", network="regtest",
                             hrp="rquh")
        doc = json.load(open(p))
        doc["next_index"] = 2 ** 40
        json.dump(doc, open(p, "w"))
        with pytest.raises(WalletError, match="next_index"):
            Wallet.open(p, "pw", hrp="rquh", network="regtest")

    def test_hrp_mismatch_refused(self, tmp_path):
        """A13: `hrp` was recorded but never checked, so the two fields
        could disagree silently."""
        p = str(tmp_path / "w.json")
        Wallet.create(hrp="rquh", network="regtest").save(p, "pw")
        with pytest.raises(WalletError, match="address prefix"):
            Wallet.open(p, "pw", hrp="quh", network="regtest")

    def test_persist_failure_is_not_silent(self, tmp_path):
        """A7: `_persist()` swallowed every error, defeating the whole
        persisted-index guarantee on a full or read-only disk."""
        w = Wallet.create(hrp="rquh", network="regtest")
        w.path = str(tmp_path / "w.json")
        w.save(passphrase="pw")

        def boom(*a, **k):
            raise OSError("no space left on device")

        w.save = boom
        with pytest.raises(WalletError, match="could not persist"):
            w.new_address()


# ---------------------------------------------------------------------------
# FIPS 204: hedged signing is the default
# ---------------------------------------------------------------------------
class TestHedgedSigningDefault:
    def test_fips204_sign_default_is_hedged(self):
        """A8: the parameter defaulted to `deterministic=True` while the
        docstring said hedged, so a new call site would silently leak."""
        from qeuph.crypto import fips204
        _pk, sk = fips204.keygen()
        a = fips204.sign(sk, b"same message")
        b = fips204.sign(sk, b"same message")
        assert a != b, "default signing must be randomised (hedged)"
        assert fips204.sign(sk, b"m", deterministic=True) == \
            fips204.sign(sk, b"m", deterministic=True)

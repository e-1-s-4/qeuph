"""Wallet: derivation, BIP-39 phrases, keystore, coin selection, sweeping."""
from __future__ import annotations

import json
import os
import stat

import pytest

from qeuph import constants as C
from qeuph.core.tx import Transaction
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.wallet import keystore
from qeuph.wallet.keystore import WalletError
from qeuph.wallet.keys import derive_key, derive_seed
from qeuph.wallet.mnemonic import (WORDLIST, entropy_to_mnemonic,
                                    generate_mnemonic, mnemonic_to_entropy)
from qeuph.wallet.wallet import Wallet, rpc_call


class TestDerivation:
    def test_deterministic(self):
        seed = bytes(range(32))
        assert derive_seed(seed, 0) == derive_seed(seed, 0)
        assert derive_key(seed, 3).seed == derive_seed(seed, 3)

    def test_indices_differ(self):
        seed = bytes(range(32))
        seeds = {derive_seed(seed, i) for i in range(16)}
        assert len(seeds) == 16

    def test_address_format_and_length(self):
        w = Wallet(bytes(range(32)), hrp="quh", network="mainnet")
        for i in range(3):
            a = w.address_at(i)
            assert a.startswith("quh1") and len(a) == 113
            assert addr_mod.address_to_hash(a, "quh") is not None
            assert a != w.address_at(i + 1)

    def test_address_matches_public_key_hash(self):
        w = Wallet(bytes(range(32)))
        for i in range(3):
            k = w.keys.key(i)
            assert addr_mod.pk_to_address(k.pk, w.hrp) == w.address_at(i)

    def test_seed_length_enforced(self):
        with pytest.raises(WalletError):
            Wallet(b"\x00" * 31)
        with pytest.raises(ValueError):
            derive_seed(b"\x00" * 31, 0)

    def test_negative_index_rejected(self):
        w = Wallet(bytes(range(32)))
        with pytest.raises(WalletError):
            w.address_at(-1)

    def test_hrp_is_honoured(self):
        w = Wallet(bytes(range(32)), hrp="rquh", network="regtest")
        assert w.address_at(0).startswith("rquh1")
        assert addr_mod.address_to_hash(w.address_at(0), "quh") is None

    def test_find_index(self):
        w = Wallet(bytes(range(32)))
        assert w.find_index(w.address_at(4)) == 4
        assert w.find_index("rquh1notanaddress") == -1

    def test_can_sign_with_derived_key(self):
        w = Wallet(bytes(range(32)))
        from qeuph.core.tx import TxIn, TxOut
        tx = Transaction([TxIn(bytes(64), 0, 1)],
                         [TxOut(10 ** 8, bytes(64))])
        tx.sign([w.keys.key(0).seed])
        assert ml_dsa.verify(w.keys.key(0).pk, tx.signing_message(0),
                             tx.inputs[0].signature)


class TestMnemonic:
    def test_wordlist_is_the_bip39_english_list(self):
        assert len(WORDLIST) == 2048
        assert len(set(WORDLIST)) == 2048
        assert WORDLIST[0] == "abandon"
        assert WORDLIST[2047] == "zoo"
        assert WORDLIST == sorted(WORDLIST)

    def test_official_vector_zero(self):
        e = bytes(32)
        assert entropy_to_mnemonic(e) == " ".join(["abandon"] * 23 + ["art"])
        assert mnemonic_to_entropy(" ".join(["abandon"] * 23 + ["art"])) == e

    def test_official_vector_max(self):
        e = b"\xff" * 32
        assert entropy_to_mnemonic(e) == " ".join(["zoo"] * 23 + ["vote"])
        assert mnemonic_to_entropy(" ".join(["zoo"] * 23 + ["vote"])) == e

    def test_every_index_is_reachable(self):
        """The 24th word's index can be 2047; a truncated wordlist would make
        `WORDLIST[2047]` raise for 1 entropy in 2048."""
        seen = set()
        for i in range(0, 2048, 1):
            e = (i * 0x01010101010101010101010101010101
                 & ((1 << 256) - 1)).to_bytes(32, "big")
            phrase = entropy_to_mnemonic(e)
            seen.add(phrase.split()[-1])
        assert len(seen) > 200

    def test_roundtrip_random(self):
        for _ in range(200):
            e = os.urandom(32)
            assert mnemonic_to_entropy(entropy_to_mnemonic(e)) == e

    def test_checksum_enforced(self):
        words = entropy_to_mnemonic(bytes(32)).split()
        words[-1] = "zoo" if words[-1] != "zoo" else "vote"
        with pytest.raises(ValueError, match="checksum"):
            mnemonic_to_entropy(" ".join(words))

    def test_word_count_enforced(self):
        with pytest.raises(ValueError, match="24 words"):
            mnemonic_to_entropy("abandon abandon")

    def test_unknown_word_rejected(self):
        with pytest.raises(ValueError, match="dictionary"):
            mnemonic_to_entropy(" ".join(["notaword"] * 24))

    def test_wrong_entropy_length_rejected(self):
        with pytest.raises(ValueError, match="32 bytes"):
            entropy_to_mnemonic(bytes(16))

    def test_generate_is_random(self):
        a, b = generate_mnemonic(), generate_mnemonic()
        assert a != b
        assert len(a.split()) == 24

    def test_wallet_phrase_roundtrip(self):
        w = Wallet.create(hrp="quh")
        w2 = Wallet.from_mnemonic(w.to_mnemonic(), hrp="quh")
        assert w2.master_seed == w.master_seed
        assert w2.address_at(0) == w.address_at(0)


class TestKeystore:
    def test_roundtrip_encrypted(self, tmp_path):
        p = str(tmp_path / "w.json")
        seed = os.urandom(32)
        keystore.save_wallet(p, seed, "correct horse", "regtest", hrp="rquh")
        assert keystore.load_wallet(p, "correct horse") == seed
        with pytest.raises(WalletError, match="passphrase"):
            keystore.load_wallet(p, "wrong")

    def test_roundtrip_unencrypted(self, tmp_path):
        p = str(tmp_path / "w.json")
        seed = os.urandom(32)
        keystore.save_wallet(p, seed, None)
        assert keystore.load_wallet(p, None) == seed
        assert keystore.load_wallet(p, "") == seed

    @pytest.mark.skipif(os.name == "nt",
                       reason="Windows has no POSIX mode bits; os.chmod "
                              "only toggles the read-only attribute, so the "
                              "0600 guarantee is a POSIX-only property")
    def test_file_permissions(self, tmp_path):
        p = str(tmp_path / "w.json")
        keystore.save_wallet(p, os.urandom(32), "pw")
        mode = stat.S_IMODE(os.stat(p).st_mode)
        assert mode == 0o600, oct(mode)

    def test_metadata_readable_without_passphrase(self, tmp_path):
        p = str(tmp_path / "w.json")
        keystore.save_wallet(p, os.urandom(32), "pw", "testnet", hrp="tquh",
                             next_index=7)
        doc = keystore.load_wallet_doc(p)
        assert doc["network"] == "testnet"
        assert doc["hrp"] == "tquh"
        assert doc["next_index"] == 7
        assert doc["kdf"]["name"] == "pbkdf2-hmac-sha3-512"
        assert doc["kdf"]["iterations"] >= 60_000
        assert "master" not in json.dumps(doc).lower() or "seed" not in \
            json.dumps(doc).lower()

    def test_no_temp_file_left(self, tmp_path):
        p = str(tmp_path / "w.json")
        keystore.save_wallet(p, os.urandom(32), "pw")
        assert not [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]

    def test_reencrypt(self, tmp_path):
        p = str(tmp_path / "w.json")
        seed = os.urandom(32)
        keystore.save_wallet(p, seed, "old", "regtest", next_index=3,
                             hrp="rquh")
        keystore.reencrypt(p, "old", "new")
        assert keystore.load_wallet(p, "new") == seed
        assert keystore.load_wallet_doc(p)["next_index"] == 3
        assert keystore.load_wallet_doc(p)["hrp"] == "rquh"
        with pytest.raises(WalletError):
            keystore.load_wallet(p, "old")

    def test_corrupt_file_rejected(self, tmp_path):
        p = str(tmp_path / "w.json")
        with open(p, "w") as f:
            f.write("{not json")
        with pytest.raises(WalletError, match="JSON"):
            keystore.load_wallet(p, None)

    def test_foreign_file_rejected(self, tmp_path):
        p = str(tmp_path / "w.json")
        with open(p, "w") as f:
            json.dump({"format": "bitcoin"}, f)
        with pytest.raises(WalletError, match="not a qeuph wallet"):
            keystore.load_wallet(p, None)

    def test_missing_file_rejected(self, tmp_path):
        with pytest.raises(WalletError, match="not found"):
            keystore.load_wallet(str(tmp_path / "nope.json"), None)

    def test_iteration_override_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("QEUPH_WALLET_KDF_ITERATIONS", "1000")
        assert keystore.kdf_iterations() == 1000
        monkeypatch.setenv("QEUPH_WALLET_KDF_ITERATIONS", "not-a-number")
        assert keystore.kdf_iterations() == keystore.KDF_ITERATIONS


class TestWalletFile:
    def test_create_save_open(self, tmp_path):
        p = str(tmp_path / "w.json")
        w = Wallet.create(hrp="rquh", network="regtest")
        w.save(p, "pw")
        w2 = Wallet.open(p, "pw", hrp="rquh", network="regtest")
        assert w2.master_seed == w.master_seed
        assert w2.address_at(0) == w.address_at(0)

    def test_network_mismatch_refused(self, tmp_path):
        p = str(tmp_path / "w.json")
        w = Wallet.create(hrp="rquh", network="regtest")
        w.save(p, "pw")
        with pytest.raises(WalletError, match="created for"):
            Wallet.open(p, "pw", hrp="quh", network="mainnet")
        # ... and can be overridden for recovery work
        w3 = Wallet.open(p, "pw", hrp="quh", network="mainnet",
                         allow_network_mismatch=True)
        assert w3.master_seed == w.master_seed
        assert w3.address_at(0).startswith("quh1")

    def test_next_index_persisted(self, tmp_path):
        p = str(tmp_path / "w.json")
        w = Wallet(bytes(range(32)), hrp="rquh", network="regtest", path=p,
                   passphrase="pw")
        w.save()
        a1 = w.new_address()
        w2 = Wallet.open(p, "pw", hrp="rquh", network="regtest")
        assert w2.next_index == 1
        a2 = w2.new_address()
        w3 = Wallet.open(p, "pw", hrp="rquh", network="regtest")
        assert w3.new_address() not in (a1, a2), "address reuse after restart"

    def test_hrp_stored_in_file(self, tmp_path):
        p = str(tmp_path / "w.json")
        w = Wallet.create(hrp="rquh", network="regtest")
        w.save(p, None)
        assert keystore.load_wallet_doc(p)["hrp"] == "rquh"
        assert keystore.load_wallet_doc(p)["network"] == "regtest"


class TestCoinSelection:
    def _wallet_with(self, utxos, nonce=0):
        w = Wallet.create(hrp="rquh", network="regtest")
        w.fetch_utxos = lambda a, u, matured_only=True: utxos
        w.fetch_nonce = lambda a, u: nonce
        return w

    def test_exact_match_needs_no_change(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 8)])
        tx = w.build_transaction(0, [(w.address_at(1), 5 * 10 ** 7)],
                                 fee=5 * 10 ** 7, rpc_url="x")
        assert len(tx.outputs) == 1
        assert tx.outputs[0].value == 5 * 10 ** 7

    def test_largest_first_with_change(self):
        small = (b"\x01" * 64, 0, 10 ** 8)
        big = (b"\x02" * 64, 0, 90 * 10 ** 7)
        w = self._wallet_with([small, big])
        tx = w.build_transaction(0, [(w.address_at(1), 5 * 10 ** 7)],
                                 fee=10 ** 6, rpc_url="x")
        assert len(tx.outputs) == 2
        assert tx.outputs[0].value == 5 * 10 ** 7
        # the single largest output covers the payment, so only it is spent
        assert tx.inputs[0].prev_txid == big[0]
        assert sum(o.value for o in tx.outputs) + 10 ** 6 == big[2]

    def test_insufficient_funds_message(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 7)])
        with pytest.raises(WalletError, match="insufficient funds"):
            w.build_transaction(0, [(w.address_at(1), 10 ** 8)],
                                fee=10 ** 6, rpc_url="x")

    def test_no_utxos_message_mentions_maturity(self):
        w = self._wallet_with([])
        with pytest.raises(WalletError, match="coinbase outputs need"):
            w.build_transaction(0, [(w.address_at(1), 10 ** 6)],
                                fee=10 ** 6, rpc_url="x")

    def test_dust_change_becomes_fee(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 8)])
        # a change of 500 quphi is below the dust threshold, so it is not
        # created as a UTXO and stays with the miner as fee
        tx = w.build_transaction(0, [(w.address_at(1),
                                      10 ** 8 - 10 ** 6 - 500)],
                                 fee=10 ** 6, rpc_url="x")
        assert len(tx.outputs) == 1
        assert tx.outputs[0].value == 10 ** 8 - 10 ** 6 - 500

    def test_dust_recipient_rejected(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 9)])
        with pytest.raises(WalletError, match="dust threshold"):
            w.build_transaction(0, [(w.address_at(1), C.DUST_THRESHOLD)],
                                fee=10 ** 6, rpc_url="x")

    def test_fresh_change_address(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 8)])
        sender = w.address_at(0)
        tx = w.build_transaction(0, [(w.address_at(1), 10 ** 7)],
                                 fee=10 ** 6, rpc_url="x",
                                 fresh_change=True)
        change = tx.outputs[-1]
        assert addr_mod.hash_to_address(change.addr_hash, "rquh") != sender
        assert change.addr_hash == w.address_hash_at(w.next_index - 1)

    def test_change_to_sender_when_disabled(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 8)])
        tx = w.build_transaction(0, [(w.address_at(1), 10 ** 7)],
                                 fee=10 ** 6, rpc_url="x",
                                 fresh_change=False)
        assert tx.outputs[-1].addr_hash == w.address_hash_at(0)

    def test_bad_recipient_rejected(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 8)])
        with pytest.raises(WalletError, match="invalid recipient"):
            w.build_transaction(0, [("quh1wrongnetwork", 10 ** 7)],
                                fee=10 ** 6, rpc_url="x")

    def test_no_recipients_rejected(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 8)])
        with pytest.raises(WalletError, match="no recipients"):
            w.build_transaction(0, [], fee=10 ** 6, rpc_url="x")

    def test_missing_rpc_url_rejected(self):
        w = Wallet.create(hrp="rquh", network="regtest")
        with pytest.raises(WalletError, match="(?i)rpc url is required"):
            w.fetch_utxos(w.address_at(0), None)

    def test_lock_time_carried(self):
        w = self._wallet_with([(b"\x01" * 64, 0, 10 ** 8)])
        tx = w.build_transaction(0, [(w.address_at(1), 10 ** 7)],
                                 fee=10 ** 6, rpc_url="x", lock_time=500_000)
        assert tx.lock_time == 500_000


class TestSweep:
    def test_sweep_chains_one_transaction_per_output(self):
        w = Wallet.create(hrp="rquh", network="regtest")
        utxos = [(bytes([i]) * 64, 0, (i + 1) * 10 ** 8) for i in range(3)]
        w.fetch_utxos = lambda a, u, matured_only=True: utxos
        w.fetch_nonce = lambda a, u: 0
        dest = w.address_at(9)
        txs = w.sweep(0, dest, "x")
        assert len(txs) == 3
        # nonces must be strictly increasing: one input per address per tx
        nonces = [t.inputs[0].txnonce for t in txs]
        assert nonces == [1, 2, 3]
        # every transaction spends a different outpoint
        ops = {(t.inputs[0].prev_txid, t.inputs[0].prev_index) for t in txs}
        assert len(ops) == 3
        for t in txs:
            assert t.outputs[0].addr_hash == w.address_hash_at(9)
            assert t.outputs[0].value > C.DUST_THRESHOLD

    def test_sweep_rejects_bad_destination(self):
        w = Wallet.create(hrp="rquh", network="regtest")
        w.fetch_utxos = lambda a, u, matured_only=True: [(b"\x01" * 64, 0,
                                                          10 ** 8)]
        w.fetch_nonce = lambda a, u: 0
        with pytest.raises(WalletError, match="invalid destination"):
            w.sweep(0, "quh1mainnetaddress", "x")

    def test_sweep_nothing_to_do(self):
        w = Wallet.create(hrp="rquh", network="regtest")
        w.fetch_utxos = lambda a, u, matured_only=True: []
        with pytest.raises(WalletError, match="nothing to sweep"):
            w.sweep(0, w.address_at(1), "x")


class TestRpcClient:
    def test_unreachable_node_message(self):
        with pytest.raises(WalletError, match="cannot reach node RPC"):
            rpc_call("http://127.0.0.1:1/", "getblockcount")

    def test_error_object_raised(self, tmp_path):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                self.rfile.read(n)
                body = json.dumps({"jsonrpc": "2.0", "id": 1,
                                   "error": {"code": -32000,
                                             "message": "nope"}}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with pytest.raises(WalletError, match="rpc getblockcount error"):
                rpc_call(f"http://127.0.0.1:{srv.server_address[1]}/",
                         "getblockcount")
        finally:
            srv.shutdown()
            srv.server_close()

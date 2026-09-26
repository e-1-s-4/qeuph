"""Wallet + keystore tests."""
import os
import tempfile

import pytest

from qeuph.crypto import ml_dsa
from qeuph.wallet import keystore
from qeuph.wallet.keys import derive_key, derive_seed
from qeuph.wallet import Wallet


class TestDerivation:
    def test_deterministic(self):
        seed = bytes(3) * 10 + bytes(2)
        k1 = derive_key(seed, 0)
        k2 = derive_key(seed, 0)
        assert k1.address == k2.address
        assert k1.pk == k2.pk
        assert k1.sk == k2.sk

    def test_indices_differ(self):
        seed = os.urandom(32)
        assert derive_key(seed, 0).address != derive_key(seed, 1).address

    def test_address_format(self):
        k = derive_key(os.urandom(32), 0)
        assert k.address.startswith("quh1")
        assert len(k.address) == 113   # 3 + 1 + 103 + 6


class TestKeystore:
    def test_roundtrip_encrypted(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.json")
            seed = os.urandom(32)
            keystore.save_wallet(path, seed, "hunter2")
            assert keystore.load_wallet(path, "hunter2") == seed
            with pytest.raises(keystore.WalletError):
                keystore.load_wallet(path, "wrong")
            with pytest.raises(keystore.WalletError):
                keystore.load_wallet(path, None)

    def test_roundtrip_unencrypted(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.json")
            seed = os.urandom(32)
            keystore.save_wallet(path, seed, None)
            assert keystore.load_wallet(path, None) == seed

    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.json")
            keystore.save_wallet(path, os.urandom(32), "x")
            assert os.stat(path).st_mode & 0o777 == 0o600


class TestWalletObject:
    def test_create_save_open(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "w.json")
            w = Wallet.create()
            addr0 = w.address_at(0)
            w.save(path, "pw")
            w2 = Wallet.open(path, "pw")
            assert w2.address_at(0) == addr0
            assert w2.master_seed == w.master_seed

    def test_new_address_sequence(self):
        w = Wallet.create()
        a = [w.new_address() for _ in range(3)]
        assert len(set(a)) == 3
        assert w.address_at(0) == a[0]

    def test_seed_can_sign(self):
        w = Wallet.create()
        k = w.keys.key(0)
        sig = ml_dsa.sign_with_seed(k.seed, b"wallet test")
        assert ml_dsa.verify(k.pk, b"wallet test", sig)
        assert ml_dsa.verify_pure(k.pk, b"wallet test", sig)

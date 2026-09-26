"""Tests for BIP-39 mnemonic phrase derivation and restore."""
from qeuph.wallet import mnemonic
from qeuph.wallet import Wallet


class TestMnemonic:
    def test_generate_and_restore(self):
        phrase = mnemonic.generate_mnemonic()
        words = phrase.split()
        assert len(words) == 24
        entropy = mnemonic.mnemonic_to_entropy(phrase)
        assert len(entropy) == 32
        recovered = mnemonic.entropy_to_mnemonic(entropy)
        assert recovered == phrase

    def test_wallet_from_mnemonic(self):
        w1 = Wallet.create()
        phrase = w1.to_mnemonic()
        w2 = Wallet.from_mnemonic(phrase)
        assert w1.master_seed == w2.master_seed
        assert w1.address_at(0) == w2.address_at(0)
        assert w1.address_at(1) == w2.address_at(1)

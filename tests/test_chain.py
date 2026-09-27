"""Chain manager + mempool integration tests on the regtest network."""
import shutil

import pytest

from qeuph.config import REGTEST
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.core.validation import TxValidationError, validate_tx


def _hdr_bytes(header, nonce):
    h = header
    return b"".join([
        h.version.to_bytes(4, "little"), h.prev_hash, h.merkle_root,
        h.timestamp.to_bytes(8, "little"), h.bits.to_bytes(4, "little"),
        h.height.to_bytes(8, "little"), nonce.to_bytes(16, "little")])
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa

TMP = "/tmp/qeuph-tests-chain"


@pytest.fixture()
def net():
    shutil.rmtree(TMP, ignore_errors=True)
    return REGTEST.with_(data_dir=TMP)


@pytest.fixture()
def miner_keys():
    seed, pk, _ = ml_dsa.generate_keypair()
    return seed, pk, addr_mod.pk_to_hash(pk)


def mine(cm, payout_hash, txs=None, n=1):
    """Mine n blocks; returns list of blocks."""
    blocks = []
    for _ in range(n):
        b, _ = cm.create_block_template(payout_hash, txs or [])
        b.mine()
        cm.connect_block(b)
        blocks.append(b)
        txs = None
    return blocks


class TestChain:
    def test_genesis_deterministic(self, net):
        cm = ChainManager(net)
        h1 = cm.genesis.hash
        cm2 = ChainManager(net)
        assert cm2.genesis.hash == h1

    def test_persistence_reload(self, net, miner_keys):
        _, _, ah = miner_keys
        cm = ChainManager(net)
        mine(cm, ah, n=3)
        tip = cm.tip_hash()
        height = cm.height()
        balance = cm.state.balance(ah)
        if cm.store:
            cm.store.close()
        cm2 = ChainManager(net)
        assert cm2.height() == height
        assert cm2.tip_hash() == tip
        assert cm2.state.balance(ah) == balance

    def test_block_template_reward(self, net, miner_keys):
        _, _, ah = miner_keys
        cm = ChainManager(net)
        b, reward = cm.create_block_template(ah, [])
        assert reward == 50 * 10**8
        b.mine()
        cm.connect_block(b)
        assert cm.state.balance(ah) == 50 * 10**8

    def test_reward_epoch_boundary(self, net, miner_keys):
        # simulate heights near the first epoch boundary via direct rewards
        from qeuph.core import reward as reward_mod
        assert reward_mod.block_reward(210_000 - 1) == 5_000_000_000
        assert reward_mod.block_reward(210_000) == 3_333_333_333

    def test_bad_pow_rejected(self, net, miner_keys):
        from qeuph.core import pow as pow_mod
        _, _, ah = miner_keys
        cm = ChainManager(net)
        b, _ = cm.create_block_template(ah, [])
        b.mine()
        # find a nonce that definitely breaks PoW (regtest target is easy)
        bad = b.header.nonce + 1
        while pow_mod.check_pow(_hdr_bytes(b.header, bad), b.header.bits):
            bad += 1
        b.header.nonce = bad
        from qeuph.core.validation import BlockValidationError
        with pytest.raises(BlockValidationError, match="proof of work"):
            cm.connect_block(b)

    def test_wrong_bits_rejected(self, net, miner_keys):
        _, _, ah = miner_keys
        cm = ChainManager(net)
        b, _ = cm.create_block_template(ah, [])
        b.mine()
        b2, _ = cm.create_block_template(ah, [])
        b2.header.bits = 0x403FFFFF   # easier than required
        from qeuph.core.validation import BlockValidationError
        with pytest.raises(BlockValidationError, match="bits"):
            cm.connect_block(b2)

    def test_double_spend_in_same_block_rejected(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=1)
        cb_txid = blocks[0].transactions[0].txid()
        other = addr_mod.pk_to_hash(ml_dsa.generate_keypair()[1])
        # two txs spending the same UTXO (second has nonce 2 -> stale)
        tx1 = Transaction([TxIn(cb_txid, 0, 1)], [TxOut(1 * 10**8, other)])
        tx1.sign([seed])
        tx2 = Transaction([TxIn(cb_txid, 0, 2)], [TxOut(1 * 10**8, other)])
        tx2.sign([seed])
        # tx1 valid, tx2 fails nonce ordering
        with pytest.raises(TxValidationError):
            validate_tx(tx2, cm.state, cm.height())


class TestFullFlow:
    def test_mine_spend_relay_flow(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        mp = Mempool(cm.state_provider(), fee_rate=0, height_fn=cm.height)
        # mine 101 blocks (coinbase of block 1 matures at 101)
        blocks = mine(cm, ah, n=101)
        assert cm.height() == 101
        matured = cm.state.balance(ah, matured_only=True)
        assert matured == 101 * 50 * 10**8

        # spend matured coinbase with fee
        other_seed, other_pk, _ = ml_dsa.generate_keypair()
        other = addr_mod.pk_to_hash(other_pk)
        tx = Transaction([TxIn(blocks[0].transactions[0].txid(), 0, 1)],
                         [TxOut(25 * 10**8, other),
                          TxOut(24 * 10**8 + 99990000, ah)])
        tx.sign([seed])
        mp.add_tx(tx)
        assert len(mp) == 1
        # duplicate rejected
        with pytest.raises(TxValidationError):
            mp.add_tx(tx)
        # build block from mempool
        chosen = mp.best_transactions(2_000_000)
        assert chosen == [tx]
        b, reward = cm.create_block_template(ah, chosen)
        assert reward == 50 * 10**8 + 10000
        b.mine()
        cm.connect_block(b)
        mp.on_new_block(b)
        assert len(mp) == 0
        assert cm.state.balance(other) == 25 * 10**8
        assert cm.state.nonce_of(ah) == 1

        # second spend from change (nonce 2)
        tx2 = Transaction([TxIn(tx.txid(), 1, 2)],
                          [TxOut(24 * 10**8, other)])
        tx2.sign([seed])
        validate_tx(tx2, cm.state, cm.height())
        mp.add_tx(tx2)
        b2, _ = cm.create_block_template(ah, mp.best_transactions(2_000_000))
        b2.mine()
        cm.connect_block(b2)
        mp.on_new_block(b2)
        assert cm.state.balance(other) == 49 * 10**8


class TestMempool:
    def test_nonce_chaining_in_pool(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        mp = Mempool(cm.state_provider(), fee_rate=0, height_fn=cm.height)
        blocks = mine(cm, ah, n=101)
        cb_txid = blocks[0].transactions[0].txid()
        other = bytes(64)
        # nonce 2 arrives before nonce 1 -> rejected (ordering)
        tx2 = Transaction([TxIn(cb_txid, 0, 2)], [TxOut(1 * 10**8, other)])
        tx2.sign([seed])
        with pytest.raises(TxValidationError):
            mp.add_tx(tx2)
        # nonce 1 accepted
        tx1 = Transaction([TxIn(cb_txid, 0, 1)], [TxOut(1 * 10**8, other)])
        tx1.sign([seed])
        mp.add_tx(tx1)
        # nonce 1 replay rejected
        with pytest.raises(TxValidationError):
            mp.add_tx(tx1)

"""Persistence, crash safety, and the store's atomicity guarantees."""
from __future__ import annotations

import pytest

from qeuph import constants as C
from qeuph.core.chain import ChainManager
from qeuph.core.state import ChainState
from qeuph.core.tx import TxIn, TxOut, Transaction
from qeuph.crypto import ml_dsa
from qeuph.db.store import SCHEMA_VERSION, Store

from .conftest import mine


def side_block(cm, prev, payout_hash, extra=b"side"):
    """A mined block extending an arbitrary parent with the right height,
    coinbase and bits for its own branch."""
    from qeuph.core import reward as reward_mod
    from qeuph.core.block import Block
    from qeuph.core.tx import make_coinbase
    height = prev.height + 1
    coinbase = make_coinbase(height, payout_hash,
                             reward_mod.block_reward(height), data=extra)
    return Block.build(prev.hash, height, prev.header.bits, [coinbase],
                       timestamp=prev.header.timestamp + 1,
                       min_timestamp=prev.header.timestamp + 1)


class TestStoreBasics:
    def test_schema_version_recorded(self, tmp_path):
        s = Store(str(tmp_path / "a.db"))
        try:
            assert int.from_bytes(s.get_meta("schema"), "little") == \
                SCHEMA_VERSION
        finally:
            s.close()

    def test_incompatible_schema_wipes(self, tmp_path):
        path = str(tmp_path / "b.db")
        s = Store(path)
        s.set_meta("schema", (1).to_bytes(4, "little"))
        s.close()
        s2 = Store(path)
        try:
            assert int.from_bytes(s2.get_meta("schema"), "little") == \
                SCHEMA_VERSION
            assert s2.get_meta("tip") is None
        finally:
            s2.close()

    def test_work_blob_orders_numerically(self, tmp_path):
        s = Store(str(tmp_path / "c.db"))
        try:
            s._db.execute("CREATE TABLE w (v BLOB)")
            from qeuph.db.store import _pack_work
            for v in (2 ** 500, 2 ** 200, 2 ** 64, 5):
                s._db.execute("INSERT INTO w VALUES (?)", (_pack_work(v),))
            got = [r[0] for r in s._db.execute("SELECT v FROM w ORDER BY v DESC")]
            assert [int.from_bytes(g, "big") for g in got] == \
                [2 ** 500, 2 ** 200, 2 ** 64, 5]
        finally:
            s.close()

    def test_transaction_rolls_back_on_error(self, tmp_path):
        s = Store(str(tmp_path / "d.db"))
        try:
            with pytest.raises(RuntimeError):
                with s.transaction():
                    s.set_meta("k", b"v")
                    raise RuntimeError("boom")
            assert s.get_meta("k") is None
        finally:
            s.close()

    def test_nested_transactions_commit_once(self, tmp_path):
        s = Store(str(tmp_path / "e.db"))
        try:
            with s.transaction():
                s.set_meta("a", b"1")
                with s.transaction():
                    s.set_meta("b", b"2")
            assert s.get_meta("a") == b"1" and s.get_meta("b") == b"2"
        finally:
            s.close()

    def test_wal_mode(self, tmp_path):
        s = Store(str(tmp_path / "f.db"))
        try:
            mode = s._db.execute("PRAGMA journal_mode").fetchone()[0]
            assert mode.lower() == "wal"
        finally:
            s.close()

    def test_bans_roundtrip_and_expire(self, tmp_path):
        import time
        s = Store(str(tmp_path / "g.db"))
        try:
            s.ban_peer("1.2.3.4:19090", time.time() + 600, 120, "spam")
            assert s.is_banned("1.2.3.4:19090")
            assert s.ban_count() == 1
            s.ban_peer("5.6.7.8:19090", time.time() - 10, 100, "old")
            assert not s.is_banned("5.6.7.8:19090")
            assert len(s.list_bans()) == 1
            assert s.clear_bans() >= 1
        finally:
            s.close()


class TestChainPersistence:
    def test_reload_restores_state_exactly(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        mine(cm, ah, n=120)
        before_bal = cm.state.balance(ah)
        before_nonce = cm.state.nonce_of(ah)
        before_tip = cm.tip_hash()
        before_utxos = len(cm.state.utxos)
        cm.close()

        cm2 = ChainManager(net)
        try:
            assert cm2.height() == 120
            assert cm2.tip_hash() == before_tip
            assert cm2.state.balance(ah) == before_bal
            assert cm2.state.nonce_of(ah) == before_nonce
            assert len(cm2.state.utxos) == before_utxos
            assert cm2.state.balance(ah, matured_only=True) > 0
        finally:
            cm2.close()

    def test_incremental_deltas_match_a_full_replay(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        mine(cm, ah, n=101)
        other_seed, other_pk, _ = ml_dsa.generate_keypair()
        from qeuph.crypto import address as addr_mod
        other = addr_mod.pk_to_hash(other_pk)
        cb = cm.get_block_by_height(1).transactions[0].txid()
        tx = Transaction([TxIn(cb, 0, 1)],
                         [TxOut(25 * 10 ** 8, other),
                          TxOut(24 * 10 ** 8 + 99990000, ah)])
        tx.sign([seed])
        mine(cm, ah, n=1, txs=[tx])

        incremental = {k: v.value for k, v in cm.state.utxos.items()}
        nonces = dict(cm.state.nonces)
        height = cm.height()
        cm.close()

        # rebuild by replaying every canonical block from scratch
        cm2 = ChainManager(net)
        try:
            cm2.reindex(prune=False, drop_side=False)
            assert cm2.height() == height
            assert {k: v.value for k, v in cm2.state.utxos.items()} == incremental
            assert cm2.state.nonces == nonces
        finally:
            cm2.close()

    def test_verify_chain_accepts_a_valid_chain(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            mine(cm, ah, n=30)
            rep = cm.verify_chain()
            assert rep["ok"] and rep["checked"] == 30
        finally:
            cm.close()

    def test_corrupt_main_index_is_repaired_on_load(self, net, miner_keys):
        """A hole in the canonical index must never be loaded silently: the
        node replays what it can prove and truncates to the last intact
        block, keeping state and index in agreement."""
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=20)
        # delete a canonical index row behind the store's back
        with cm.store.transaction():
            cm.store._db.execute("DELETE FROM main_chain WHERE height=10")
        cm.close()

        cm2 = ChainManager(net)
        try:
            assert cm2.height() == 9, "truncated to the last intact block"
            assert cm2.tip_hash() == blocks[8].hash
            ok, why = cm2.store.verify_main_chain(cm2.genesis.hash)
            assert ok, why
            # the UTXO table was rebuilt by the replay, so it matches the tip
            assert cm2.state.balance(ah) == 9 * 50 * C.QUPHI_PER_QUH
            assert cm2.store.count_utxos() == len(cm2.state.utxos)
        finally:
            cm2.close()

    def test_tx_index_ignores_side_chain_entries(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            blocks = mine(cm, ah, n=3)
            txid = blocks[0].transactions[0].txid()
            loc = cm.store.get_tx_block(txid)
            assert loc is not None and loc[0] == 1
            # simulate a stale index entry pointing at a non-canonical block
            with cm.store.transaction():
                cm.store._db.execute(
                    "UPDATE tx_index SET height=99 WHERE txid=?", (txid,))
            assert cm.store.get_tx_block(txid) is None
        finally:
            cm.close()

    def test_truncate_and_prune(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            mine(cm, ah, n=10)
            removed = cm.store.truncate_to_height(4)
            assert removed == 6          # heights 5..10
            assert cm.store.main_chain_height() == 4
            assert cm.store.verify_main_chain(cm.genesis.hash)[0]
            rep = cm.reindex(prune=True, drop_side=True)
            assert rep["tip"] == 4
        finally:
            cm.close()

    def test_reindex_keeps_side_chains_when_asked(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            mine(cm, ah, n=2)
            before = cm.store.count_blocks()
            rep = cm.reindex(prune=False, drop_side=False)
            assert rep["blocks"] == 2
            assert cm.store.count_blocks() == before
        finally:
            cm.close()

    def test_store_close_is_idempotent(self, net):
        cm = ChainManager(net)
        cm.close()
        cm.close()
        assert cm.store is None


class TestUndoAndState:
    def test_apply_undo_roundtrip(self, net, miner_keys):
        """The undo log must restore the exact pre-block state."""
        from qeuph.core.state import UndoBlock
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            blocks = mine(cm, ah, n=5)
            # replay the same five blocks into a SCRATCH state that starts at
            # genesis, so the comparison is meaningful
            scratch = ChainState()
            scratch.apply_block(cm.genesis)
            before = {k: (v.value, v.addr_hash, v.is_coinbase, v.cb_height)
                      for k, v in scratch.utxos.items()}
            before_nonces = dict(scratch.nonces)
            before_index = {a: set(ops) for a, ops in scratch._by_addr.items()}
            undo = UndoBlock()
            for blk in blocks:
                scratch.apply_block(blk, undo)
            after = {k: (v.value, v.addr_hash, v.is_coinbase, v.cb_height)
                     for k, v in scratch.utxos.items()}
            assert after != before
            assert len(after) == len(before) + 5
            scratch.undo_block(undo)
            assert {k: (v.value, v.addr_hash, v.is_coinbase, v.cb_height)
                    for k, v in scratch.utxos.items()} == before
            assert scratch.nonces == before_nonces
            assert {a: set(ops) for a, ops in scratch._by_addr.items()} == \
                before_index
        finally:
            cm.close()

    def test_state_balance_ignores_immature_coinbase(self, net, miner_keys):
        """A coinbase is spendable exactly COINBASE_MATURITY blocks later."""
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            mine(cm, ah, n=C.COINBASE_MATURITY + 1)
            h = cm.height()
            total = cm.state.balance(ah, h)
            matured = cm.state.balance(ah, h, matured_only=True)
            # the genesis coinbase pays 0, so it creates no UTXO at all
            assert total == (C.COINBASE_MATURITY + 1) * 50 * C.QUPHI_PER_QUH
            # only the coinbase from exactly COINBASE_MATURITY blocks back
            # is mature, so at height 101 that is block 1 alone
            assert matured == 50 * C.QUPHI_PER_QUH
            assert matured < total
        finally:
            cm.close()

    def test_address_index_stays_consistent(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            mine(cm, ah, n=5)
            indexed = 0
            for a, ops in cm.state._by_addr.items():
                for op in ops:
                    assert cm.state.utxos[op].addr_hash == a
                    indexed += 1
            assert indexed == len(cm.state.utxos)
        finally:
            cm.close()

    def test_state_copy_is_independent(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            mine(cm, ah, n=2)
            snap = cm.state.copy()
            mine(cm, ah, n=1)
            assert len(snap.utxos) == 2
            assert len(cm.state.utxos) == 3
        finally:
            cm.close()


class TestStateIdentityAcrossReorg:
    def test_mempool_follows_a_replaced_state_object(self, net, miner_keys):
        """The ChainState object is REPLACED on a reorg; a mempool that cached
        the old object would validate against a stale UTXO set."""
        from qeuph.core.mempool import Mempool
        from qeuph.crypto import address as addr_mod
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            mp = Mempool(cm.state_provider(), fee_rate=0,
                         height_fn=cm.height,
                         mtp_fn=cm.median_time_past)
            mine(cm, ah, n=101)
            cb = cm.get_block_by_height(1).transactions[0].txid()
            other_seed, other_pk, _ = ml_dsa.generate_keypair()
            other = addr_mod.pk_to_hash(other_pk)
            tx = Transaction([TxIn(cb, 0, 1)],
                             [TxOut(25 * 10 ** 8, other),
                              TxOut(24 * 10 ** 8 + 99990000, ah)])
            tx.sign([seed])
            mp.add_tx(tx)
            old_state_id = id(cm.state)
            assert mp.state is cm.state
            assert not mp.state_is_stale()

            # build a longer side chain that does not contain the spend
            prev = cm.genesis
            for i in range(103):
                b = side_block(cm, prev, other, extra=b"side%d" % (i % 256))
                b.mine()
                cm.connect_block(b, current_time=b.header.timestamp)
                prev = b
            assert cm.height() == 101, "the main chain has not moved"
            assert cm.consider_reorg()
            assert cm.height() == 103
            assert id(cm.state) != old_state_id, "reorg must replace the object"
            assert mp.state is cm.state
            # the spend is gone with the old chain, so the pool must drop it
            assert mp.resync() >= 1
            assert len(mp) == 0
            assert cm.state.nonce_of(ah) == 0
        finally:
            cm.close()

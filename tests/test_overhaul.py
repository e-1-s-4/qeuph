"""Tests for the mainnet-readiness overhaul: reorg, mempool fees,
lock time, persistence, node shutdown, protocol hardening."""
import asyncio
import dataclasses
import socket
import time

import pytest

from qeuph import constants as C
from qeuph.config import REGTEST
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.state import UndoBlock
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.core.validation import (BlockValidationError, TxValidationError,
                                   validate_tx)
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.node.node import QNode

@pytest.fixture()
def net(tmp_path):
    """A private regtest profile per test.

    A fixed `/tmp/...` directory cannot be reused here: the ChainManager
    holds its SQLite store open, so on Windows `rmtree(ignore_errors=True)`
    silently fails and the next test reopens the previous test's chain
    instead of a fresh one.
    """
    return dataclasses.replace(REGTEST, data_dir=str(tmp_path / "chain"))


@pytest.fixture()
def miner_keys():
    seed, pk, _ = ml_dsa.generate_keypair()
    return seed, pk, addr_mod.pk_to_hash(pk)


def mine(cm, payout_hash, n=1, txs=None):
    blocks = []
    for _ in range(n):
        b, _ = cm.create_block_template(payout_hash, txs or [])
        b.mine()
        res = cm.connect_block(b)
        assert res.connected
        blocks.append(b)
        txs = None
    return blocks


def side_block(cm, prev, payout_hash):
    """Build a mined block extending an arbitrary parent (correct height,
    coinbase and bits for its own chain)."""
    from qeuph.core.block import Block
    from qeuph.core.tx import make_coinbase
    from qeuph.core import reward as reward_mod
    height = prev.height + 1
    coinbase = make_coinbase(height, payout_hash, reward_mod.block_reward(height))
    bits = prev.header.bits  # regtest never retargets
    return Block.build(prev.hash, height, bits, [coinbase],
                       timestamp=prev.header.timestamp + 1,
                       min_timestamp=prev.header.timestamp + 1)


# ---------------------------------------------------------------------------
# Reorganisation: a heavier side chain must take over, at any depth
# ---------------------------------------------------------------------------
class TestReorg:
    def test_side_chain_with_more_work_wins(self, net, miner_keys):
        seed, pk, ah = miner_keys
        other_seed, other_pk, _ = ml_dsa.generate_keypair()
        bh = addr_mod.pk_to_hash(other_pk)
        cm = ChainManager(net)
        # main chain: 3 blocks
        mine(cm, ah, n=3)
        assert cm.height() == 3

        # side chain: 4 blocks building on genesis (parent = genesis)
        prev = cm.genesis
        for i in range(4):
            b = side_block(cm, prev, bh)
            b.mine()
            res = cm.connect_block(b)
            if i == 0:
                # first side block is stored (not connected)
                assert not res.connected
                assert not res.orphan
            prev = b
        # 4-block side chain has more cumulative work than the 3-block chain
        assert cm.consider_reorg() is True
        assert cm.height() == 4
        assert cm.tip.hash == prev.hash
        # rewards went to the side chain miner
        assert cm.state.balance(bh) == 4 * 50 * 10**8
        assert cm.state.balance(ah) == 0

    def test_deeper_side_chain_found_incrementally(self, net, miner_keys):
        seed, pk, ah = miner_keys
        other_seed, other_pk, _ = ml_dsa.generate_keypair()
        bh = addr_mod.pk_to_hash(other_pk)
        cm = ChainManager(net)
        mine(cm, ah, n=2)
        # side chain 3 blocks on genesis
        prev = cm.genesis
        for i in range(3):
            b = side_block(cm, prev, bh)
            b.mine()
            cm.connect_block(b)
            prev = b
        assert cm.consider_reorg()
        assert cm.height() == 3
        # continue the (now main) side chain and the original chain is stale
        b, _ = cm.create_block_template(bh, [])
        b.mine()
        assert cm.connect_block(b).connected
        assert cm.height() == 4

    def test_reorg_restores_state_exactly(self, net, miner_keys):
        seed, pk, ah = miner_keys
        other_seed, other_pk, _ = ml_dsa.generate_keypair()
        bh = addr_mod.pk_to_hash(other_pk)
        cm = ChainManager(net)
        # main chain with a transaction
        blocks = mine(cm, ah, n=101)
        cb_txid = blocks[0].transactions[0].txid()
        tx = Transaction([TxIn(cb_txid, 0, 1)],
                         [TxOut(25 * 10**8, bh),
                          TxOut(24 * 10**8 + 99990000, ah)])
        tx.sign([seed])
        mine(cm, ah, n=1, txs=[tx])
        assert cm.state.balance(bh) == 25 * 10**8
        assert cm.state.nonce_of(ah) == 1

        # longer side chain without the transaction wins
        prev = cm.genesis
        for i in range(103):
            b = side_block(cm, prev, bh)
            b.mine()
            cm.connect_block(b)
            prev = b
        assert cm.consider_reorg()
        assert cm.height() == 103
        # the spend is gone with the old chain: its coinbase and outputs
        # no longer exist in the UTXO set
        assert cm.state.balance(bh) == 103 * 50 * 10**8
        assert cm.state.nonce_of(ah) == 0
        assert cm.state.get_utxo(cb_txid, 0) is None
        # spending the old-chain coinbase is impossible (missing UTXO)
        tx2 = Transaction([TxIn(cb_txid, 0, 1)], [TxOut(1 * 10**8, bh)])
        tx2.sign([seed])
        with pytest.raises(TxValidationError, match="missing UTXO"):
            validate_tx(tx2, cm.state, cm.height())


# ---------------------------------------------------------------------------
# State undo log
# ---------------------------------------------------------------------------
class TestUndo:
    def test_apply_and_undo_roundtrip(self, net, miner_keys):
        seed, pk, ah = miner_keys
        other = addr_mod.pk_to_hash(ml_dsa.generate_keypair()[1])
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        before_utxos = dict(cm.state.utxos)
        before_nonces = dict(cm.state.nonces)
        before_balance = cm.state.balance(ah)

        tx = Transaction([TxIn(blocks[0].transactions[0].txid(), 0, 1)],
                         [TxOut(25 * 10**8, other)])
        tx.sign([seed])
        undo = UndoBlock()
        cm.state.apply_transaction(tx, cm.height(), undo)
        assert cm.state.balance(ah) == before_balance - 50 * 10**8
        assert cm.state.balance(other) == 25 * 10**8
        cm.state.undo_block(undo)
        assert cm.state.utxos == before_utxos
        assert cm.state.nonces == before_nonces
        assert cm.state.balance(ah) == before_balance
        assert cm.state.balance(other) == 0

    def test_undo_address_index_consistent(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=1)
        undo = UndoBlock()
        cm.state.apply_block(blocks[0], undo)
        ops = cm.state._by_addr.get(ah, set())
        assert ops == {(blocks[0].transactions[0].txid(), 0)}
        cm.state.undo_block(undo)
        assert ah not in cm.state._by_addr


# ---------------------------------------------------------------------------
# Mempool fee ranking (regression: negative fee bug)
# ---------------------------------------------------------------------------
class TestMempoolFees:
    def test_fee_cached_and_ranked(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()
        mp = Mempool(cm.state_provider(), height_fn=cm.height,
                    mtp_fn=cm.median_time_past)
        # spend coinbase, change back to the sender (chained spend)
        rich = Transaction([TxIn(cb, 0, 1)], [TxOut(25 * 10**8, ah)])
        rich.sign([seed])
        mp.add_tx(rich)
        assert mp.get_fee(rich.txid()) == 25 * 10**8

        # second spend chained on the first (nonce 2), smaller fee
        rich2 = Transaction([TxIn(rich.txid(), 0, 2)], [TxOut(24 * 10**8, ah)])
        rich2.sign([seed])
        mp.add_tx(rich2)
        assert mp.get_fee(rich2.txid()) == 1 * 10**8
        # fees are non-negative for both pooled txs (regression: the old
        # overlay lookup made in-pool fees negative)
        assert mp.get_fee(rich.txid()) >= 0
        assert mp.get_fee(rich2.txid()) >= 0
        # best_transactions returns fee-ordered, nonce-ordered chain
        chosen = mp.best_transactions(2_000_000)
        assert rich in chosen and rich2 in chosen
        # the higher-fee parent is picked first
        assert chosen.index(rich) < chosen.index(rich2)

    def test_eviction_when_full(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()
        mp = Mempool(cm.state_provider(), height_fn=cm.height,
                    mtp_fn=cm.median_time_past)
        # shrink the budget to force eviction
        old_max = C.MAX_MEMPOOL_SIZE
        C.MAX_MEMPOOL_SIZE = 1
        try:
            with pytest.raises(TxValidationError):
                mp.add_tx(Transaction([TxIn(cb, 0, 1)], [TxOut(1, bytes(64))])
                          .sign([seed]))
        finally:
            C.MAX_MEMPOOL_SIZE = old_max


# ---------------------------------------------------------------------------
# Lock time (whitepaper Table 2)
# ---------------------------------------------------------------------------
class TestLockTime:
    def test_height_locked_tx_rejected_early(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()
        other = addr_mod.pk_to_hash(ml_dsa.generate_keypair()[1])
        tx = Transaction([TxIn(cb, 0, 1)], [TxOut(1, other)], lock_time=cm.height() + 50)
        tx.sign([seed])
        with pytest.raises(TxValidationError, match="locked"):
            validate_tx(tx, cm.state, cm.height())

    def test_height_locked_tx_valid_at_height(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()
        other = addr_mod.pk_to_hash(ml_dsa.generate_keypair()[1])
        tx = Transaction([TxIn(cb, 0, 1)], [TxOut(1 * 10**8, other)],
                         lock_time=cm.height())
        tx.sign([seed])
        validate_tx(tx, cm.state, cm.height())

    def test_mempool_respects_lock_time(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()
        mp = Mempool(cm.state_provider(), height_fn=cm.height,
                    mtp_fn=cm.median_time_past)
        tx = Transaction([TxIn(cb, 0, 1)], [TxOut(1 * 10**8, bytes(64))],
                         lock_time=cm.height() + 100)
        tx.sign([seed])
        with pytest.raises(TxValidationError, match="locked"):
            mp.add_tx(tx)

    def test_time_locked_tx(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()
        mtp = cm.median_time_past()
        tx = Transaction([TxIn(cb, 0, 1)], [TxOut(1 * 10**8, bytes(64))],
                         lock_time=mtp + 10_000)
        tx.sign([seed])
        with pytest.raises(TxValidationError, match="locked"):
            validate_tx(tx, cm.state, cm.height(), mtp=mtp)
        # final when MTP catches up
        validate_tx(tx, cm.state, cm.height(), mtp=mtp + 10_000)


# ---------------------------------------------------------------------------
# Validation hardening
# ---------------------------------------------------------------------------
class TestValidation:
    def test_zero_value_output_rejected(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()
        tx = Transaction([TxIn(cb, 0, 1)],
                         [TxOut(25 * 10**8, bytes(64)), TxOut(0, bytes(64))])
        tx.sign([seed])
        with pytest.raises(TxValidationError, match="non-positive value"):
            validate_tx(tx, cm.state, cm.height())

    def test_malformed_bits_fail_validation_not_crash(self, net, miner_keys):
        _, _, ah = miner_keys
        cm = ChainManager(net)
        b, _ = cm.create_block_template(ah, [])
        b.mine()
        b.header.bits = 0xFFFF0000  # exponent way over 512 bits
        with pytest.raises(BlockValidationError):
            cm.connect_block(b)


# ---------------------------------------------------------------------------
# Persistence: incremental UTXO deltas survive reload
# ---------------------------------------------------------------------------
class TestPersistence:
    def test_incremental_delta_reload(self, net, miner_keys):
        seed, pk, ah = miner_keys
        other = addr_mod.pk_to_hash(ml_dsa.generate_keypair()[1])
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()
        tx = Transaction([TxIn(cb, 0, 1)], [TxOut(25 * 10**8, other),
                                            TxOut(24 * 10**8 + 99990000, ah)])
        tx.sign([seed])
        mine(cm, ah, n=1, txs=[tx])
        tip, height = cm.tip_hash(), cm.height()
        bal_other, bal_ah = cm.state.balance(other), cm.state.balance(ah)
        nonce_ah = cm.state.nonce_of(ah)
        assert bal_other == 25 * 10**8
        cm.store.close()

        cm2 = ChainManager(net)
        assert cm2.height() == height
        assert cm2.tip_hash() == tip
        assert cm2.state.balance(other) == bal_other
        assert cm2.state.balance(ah) == bal_ah
        assert cm2.state.nonce_of(ah) == nonce_ah
        assert cm2.state.get_utxo(cb, 0) is None

    def test_txid_cache_invalidation(self, net):
        from qeuph.core.tx import Transaction, TxIn, TxOut
        seed, pk, _ = ml_dsa.generate_keypair()
        ah = addr_mod.pk_to_hash(pk)
        tx = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(1, ah)])
        t1 = tx.txid()
        tx.sign([seed])
        t2 = tx.txid()
        assert t1 != t2  # cache invalidated by signing


# ---------------------------------------------------------------------------
# Protocol hardening
# ---------------------------------------------------------------------------
class TestProtocol:
    def test_frame_buffer_bound(self):
        from qeuph.network.protocol import FrameReader
        r = FrameReader(max_buffer=1024)
        r.feed(b"x" * 1024)
        with pytest.raises(BufferError):
            r.feed(b"y")

    def test_addr_command_registered(self):
        from qeuph.network.protocol import COMMANDS, encode_frame
        assert "addr" in COMMANDS and "getaddr" in COMMANDS
        frame = encode_frame("addr", {"addrs": [{"host": "h", "port": 1}]})
        assert frame[:4] == C.MAGIC_BYTES

    def test_resync_keeps_tail(self):
        from qeuph.network.protocol import FrameReader
        r = FrameReader()
        r.feed(b"garbage" * 10)
        assert r.next_frame() is None
        assert len(r._buf) <= 4


# ---------------------------------------------------------------------------
# Node lifecycle: prompt shutdown with silent peers
# ---------------------------------------------------------------------------
class TestNodeShutdown:
    def test_stop_completes_with_connected_silent_peer(self, net):
        cm = ChainManager(net)
        mp = Mempool(cm.state_provider(), height_fn=cm.height,
                    mtp_fn=cm.median_time_past)

        def free_port():
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        p2p, rpc = free_port(), free_port()
        n = dataclasses.replace(net, p2p_port=p2p, rpc_port=rpc,
                                data_dir=net.data_dir + "-node")
        node = QNode(n, cm, mp)

        async def scenario():
            await node.start()
            # a raw TCP client that connects and says nothing (silent peer)
            reader, writer = await asyncio.open_connection("127.0.0.1", p2p)
            await asyncio.sleep(0.2)
            assert node.peers, "silent peer should be connected"
            t0 = time.time()
            await asyncio.wait_for(node.stop(), timeout=5.0)
            dt = time.time() - t0
            # Close AND await the client side.  A bare `writer.close()` leaves
            # the transport attached to the loop, and the Windows proactor
            # then spins forever in `asyncio.run()` teardown - a hang in the
            # test, not in the node.
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
            assert dt < 4.0, f"stop took {dt:.1f}s (deadlock?)"
            assert not node.peers

        asyncio.run(scenario())
        cm.store.close()

    def test_addr_exchange_between_peers(self, net):
        cm1 = ChainManager(net)
        cm2 = ChainManager(dataclasses.replace(net, data_dir=net.data_dir + "-b"))
        mp1 = Mempool(cm1.state_provider(), height_fn=cm1.height)
        mp2 = Mempool(cm2.state_provider(), height_fn=cm2.height)

        def free_port():
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        p1, r1 = free_port(), free_port()
        p2, r2 = free_port(), free_port()
        n1 = dataclasses.replace(net, p2p_port=p1, rpc_port=r1,
                                 data_dir=net.data_dir + "-x1")
        n2 = dataclasses.replace(net, p2p_port=p2, rpc_port=r2,
                                 data_dir=net.data_dir + "-x2")
        node1 = QNode(n1, cm1, mp1)
        node2 = QNode(n2, cm2, mp2, connect_peers=[("127.0.0.1", p1)])

        async def scenario():
            await node1.start()
            await node2.start()
            for _ in range(100):
                if node1.peers and node2.peers:
                    break
                await asyncio.sleep(0.05)
            assert node1.peers and node2.peers
            # node2 received node1's advertised address via getaddr/addr
            await asyncio.sleep(0.3)
            assert ("127.0.0.1", p1) in node2._known_addrs
            await asyncio.wait_for(node1.stop(), timeout=5.0)
            await asyncio.wait_for(node2.stop(), timeout=5.0)

        asyncio.run(scenario())
        cm1.store.close()
        cm2.store.close()


# ---------------------------------------------------------------------------
# Wallet: fresh change addresses + persistent next_index
# ---------------------------------------------------------------------------
class TestWalletPrivacy:
    def test_change_goes_to_fresh_address(self, net, miner_keys):
        seed, pk, ah = miner_keys
        from qeuph.wallet import Wallet
        w = Wallet(seed, hrp=net.hrp, network=net.name)
        assert w.address_at(0).startswith(net.hrp)
        cm = ChainManager(net)
        blocks = mine(cm, ah, n=101)
        cb = blocks[0].transactions[0].txid()

        class FakeRPC:
            def call(self, method, params):
                if method == "listutxos":
                    return {"utxos": [{"txid": cb.hex(), "index": 0,
                                       "value": 50 * 10**8}]}
                if method == "getnonce":
                    return {"nonce": 0}
                raise AssertionError(method)

        import qeuph.wallet.wallet as wmod
        orig = wmod.rpc_call
        wmod.rpc_call = lambda url, method, params=None, timeout=60: \
            FakeRPC().call(method, params)
        try:
            tx = w.build_transaction(0, [(w.address_at(5), 10 * 10**8)],
                                     fee=10**6, rpc_url="http://fake",
                                     fresh_change=True)
        finally:
            wmod.rpc_call = orig
        # change output is NOT the sender address
        out_addrs = {o.addr_hash for o in tx.outputs}
        assert addr_mod.address_to_hash(w.address_at(0), net.hrp) not in out_addrs
        # a new address was consumed (index advanced)
        assert w.next_index >= 1
        # the change is recoverable: it belongs to some derived index
        found = any(addr_mod.address_to_hash(w.address_at(i), net.hrp) in out_addrs
                    for i in range(16))
        assert found, "change output must belong to a wallet-derived address"
        # next_index advanced past the change index
        assert w.next_index >= 2

    def test_wallet_next_index_persisted(self, net, miner_keys):
        seed, pk, ah = miner_keys
        from qeuph.wallet import Wallet
        import tempfile, os
        path = os.path.join(tempfile.mkdtemp(), "w.json")
        w = Wallet(seed, hrp=net.hrp, network=net.name, path=path,
                   passphrase="pw")
        w.save()
        a1 = w.new_address()
        w.save()
        w2 = Wallet.open(path, "pw", hrp=net.hrp, network=net.name)
        assert w2.next_index == 1
        a2 = w2.new_address()
        assert a1 != a2
        # no reuse after restart
        w3 = Wallet.open(path, "pw", hrp=net.hrp, network=net.name)
        assert w3.new_address() not in (a1, a2)

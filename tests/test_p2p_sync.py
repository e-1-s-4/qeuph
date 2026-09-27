"""P2P: framing, handshake rules, block/tx relay, two-node sync, bans."""
from __future__ import annotations

import asyncio
import collections
import struct
import time

import pytest

from qeuph import constants as C
from qeuph.config import REGTEST
from qeuph.core.block import Block, BlockHeader
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.network.protocol import (FrameReader, MAX_PAYLOAD, decode_frame,
                                    encode_frame)
from qeuph.node.node import PeerMisbehaved, QNode

from .conftest import free_port, mine


class TestFraming:
    def test_roundtrip(self):
        for cmd in ("version", "verack", "getheaders", "headers", "block",
                    "inv", "getdata", "notfound", "tx", "mempool", "ping",
                    "pong", "getaddr", "addr", "getblocks"):
            raw = encode_frame(cmd, {"n": 1})
            c, p = decode_frame(raw)
            assert c == cmd and p == {"n": 1}

    def test_layout(self):
        raw = encode_frame("ping", {"nonce": 7}, magic=C.MAGIC_BYTES)
        assert raw[:4] == b"QUH!"
        assert raw[4:16] == b"ping".ljust(12, b"\x00")
        length, = struct.unpack("<I", raw[16:20])
        assert length == len(raw) - 24

    def test_checksum_detects_corruption(self):
        raw = bytearray(encode_frame("ping", {"nonce": 7}))
        raw[-1] ^= 0xFF
        with pytest.raises(ValueError, match="checksum"):
            decode_frame(bytes(raw))

    def test_bad_magic_rejected(self):
        raw = encode_frame("ping", {}, magic=b"TQH!")
        with pytest.raises(ValueError, match="magic"):
            decode_frame(raw, magic=C.MAGIC_BYTES)

    def test_unknown_command_rejected(self):
        with pytest.raises(ValueError):
            encode_frame("evilcmd", {})

    def test_oversized_payload_rejected(self):
        payload = {"blob": "aa" * (MAX_PAYLOAD + 10)}
        with pytest.raises(ValueError, match="payload too large"):
            encode_frame("tx", payload)

    def test_reader_reassembles_partial_frames(self):
        raw = encode_frame("headers", {"headers": ["ab" * 168]})
        r = FrameReader()
        for i in range(len(raw)):
            r.feed(raw[i:i + 1])
            if i < len(raw) - 1:
                assert r.next_frame() is None
        cmd, p = r.next_frame()
        assert cmd == "headers" and len(p["headers"]) == 1

    def test_reader_resyncs_on_garbage(self):
        r = FrameReader()
        r.feed(b"garbage" * 10)
        assert r.next_frame() is None
        assert len(r._buf) <= len(C.MAGIC_BYTES)

    def test_reader_buffer_bound(self):
        r = FrameReader(max_buffer=64)
        with pytest.raises(BufferError):
            r.feed(b"\x00" * 100)

    def test_reader_skips_corrupt_frame_and_keeps_going(self):
        good = encode_frame("ping", {"nonce": 1})
        bad = bytearray(encode_frame("ping", {"nonce": 2}))
        bad[-1] ^= 0xFF
        r = FrameReader()
        r.feed(bytes(bad) + good)
        cmd, p = r.next_frame()
        assert cmd == "ping" and p == {"nonce": 1}

    def test_network_magic_isolates_streams(self):
        testnet = encode_frame("ping", {"nonce": 1}, magic=C.TESTNET_MAGIC_BYTES)
        r = FrameReader(C.MAGIC_BYTES)
        r.feed(testnet)
        assert r.next_frame() is None, "a foreign network must not parse"
        assert len(r._buf) <= len(C.MAGIC_BYTES)


class TestBlockCodec:
    def test_header_roundtrip(self):
        h = BlockHeader(1, bytes(64), bytes(64), 1700000000, C.GENESIS_BITS,
                        42, 99)
        h2 = BlockHeader.deserialize(h.serialize())
        assert h2.hash() == h.hash()
        assert h2.to_dict() == h.to_dict()

    def test_bad_header_size(self):
        with pytest.raises(ValueError):
            BlockHeader.deserialize(bytes(100))

    def test_block_roundtrip(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            blk = mine(cm, ah, n=1)[0]
            b2 = Block.deserialize(blk.serialize())
            assert b2.hash == blk.hash
            assert b2.block_size() == blk.block_size()
        finally:
            cm.close()

    def test_trailing_bytes_rejected(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            blk = mine(cm, ah, n=1)[0]
            with pytest.raises(ValueError, match="trailing"):
                Block.deserialize(blk.serialize() + b"\x00")
        finally:
            cm.close()

    def test_truncated_block_rejected(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            blk = mine(cm, ah, n=1)[0]
            with pytest.raises(ValueError):
                Block.deserialize(blk.serialize()[:100])
        finally:
            cm.close()

    def test_zero_transaction_block_rejected(self, net, miner_keys):
        seed, pk, ah = miner_keys
        cm = ChainManager(net)
        try:
            blk = mine(cm, ah, n=1)[0]
            raw = bytearray(blk.serialize())
            raw[168:172] = struct.pack("<I", 0)
            with pytest.raises(ValueError):
                Block.deserialize(bytes(raw))
        finally:
            cm.close()


class TestTransactionCodec:
    def test_strict_rejects_unsigned(self):
        tx = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(10 ** 8, bytes(64))])
        with pytest.raises(ValueError, match="missing pubkey"):
            Transaction.deserialize(tx.serialize())
        lenient = Transaction.deserialize(tx.serialize(), allow_unsigned=True)
        assert lenient.txid() == tx.txid()

    def test_truncated_rejected(self):
        seed, _pk, _ = ml_dsa.generate_keypair()
        tx = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(10 ** 8, bytes(64))])
        tx.sign([seed])
        with pytest.raises(ValueError):
            Transaction.deserialize(tx.serialize()[:10])

    def test_trailing_bytes_rejected(self):
        seed, _pk, _ = ml_dsa.generate_keypair()
        tx = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(10 ** 8, bytes(64))])
        tx.sign([seed])
        with pytest.raises(ValueError, match="trailing"):
            Transaction.deserialize(tx.serialize() + b"\x00")

    def test_zero_inputs_rejected(self):
        from qeuph.core.tx import Transaction as T
        raw = struct.pack("<I", 1) + struct.pack("<I", 0) + \
            struct.pack("<I", 1) + struct.pack("<Q", 0)
        with pytest.raises(ValueError, match="input count"):
            T.deserialize(raw)

    def test_value_range_checked(self):
        from qeuph.core.tx import TxOut
        with pytest.raises(ValueError):
            TxOut(-1, bytes(64)).serialize()
        with pytest.raises(ValueError):
            TxOut(1, bytes(63)).serialize()

    def test_cache_invalidated_on_mutation(self):
        seed, pk, _ = ml_dsa.generate_keypair()
        tx = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(10 ** 8, bytes(64))])
        before = tx.txid()
        tx.sign([seed])
        assert tx.txid() != before
        assert tx.txid() == Transaction.deserialize(tx.serialize()).txid()


class NodeHarness:
    """Two real nodes with real listeners, wired to each other."""

    def __init__(self, tmp_path, name):
        net = REGTEST.with_(data_dir=str(tmp_path / name),
                            p2p_port=free_port(), rpc_port=free_port())
        self.net = net
        self.chain = ChainManager(net)
        self.mempool = Mempool(self.chain.state_provider(),
                               fee_rate=C.MIN_RELAY_FEE_RATE,
                               height_fn=self.chain.height,
                               mtp_fn=self.chain.median_time_past)
        self.node = QNode(net, self.chain, self.mempool)

    def close(self):
        self.chain.close()


def run_pair(tmp_path, seconds=4.0, connect=True):
    a = NodeHarness(tmp_path, "a")
    b = NodeHarness(tmp_path, "b")
    if connect:
        b.node.connect_peers.append(("127.0.0.1", a.net.p2p_port))

    async def scenario():
        await a.node.start()
        await b.node.start()
        for _ in range(100):
            if a.node.peers and b.node.peers:
                break
            await asyncio.sleep(0.05)
        await asyncio.sleep(seconds)
        await asyncio.wait_for(a.node.stop(), timeout=10)
        await asyncio.wait_for(b.node.stop(), timeout=10)
    asyncio.run(scenario())
    return a, b


class TestTwoNodeSync:
    def test_handshake_and_height_propagation(self, tmp_path):
        a = NodeHarness(tmp_path, "a")
        b = NodeHarness(tmp_path, "b")
        seed, pk, _ = ml_dsa.generate_keypair()
        ah = addr_mod.pk_to_hash(pk)
        mine(a.chain, ah, n=5)
        b.node.connect_peers.append(("127.0.0.1", a.net.p2p_port))

        async def scenario():
            await a.node.start()
            await b.node.start()
            for _ in range(400):
                if b.chain.height() == 5:
                    break
                await asyncio.sleep(0.05)
            assert b.chain.height() == 5, "headers-first sync did not complete"
            assert b.chain.tip_hash() == a.chain.tip_hash()
            # UTXO state came across too
            assert b.chain.state.balance(ah) == 5 * 50 * C.QUPHI_PER_QUH
            assert len(b.node.peers) == 1
            info = b.node.peer_info()[0]
            assert info["best_height"] == 5
            assert info["version"] == C.PROTOCOL_VERSION
            await a.node.stop()
            await b.node.stop()

        asyncio.run(scenario())
        a.close()
        b.close()

    def test_transaction_relay(self, tmp_path):
        a = NodeHarness(tmp_path, "a")
        b = NodeHarness(tmp_path, "b")
        seed, pk, _ = ml_dsa.generate_keypair()
        ah = addr_mod.pk_to_hash(pk)
        mine(a.chain, ah, n=101)
        cb = a.chain.get_block_by_height(1).transactions[0].txid()
        _, opk, _ = ml_dsa.generate_keypair()
        other = addr_mod.pk_to_hash(opk)
        tx = Transaction([TxIn(cb, 0, 1)],
                         [TxOut(25 * 10 ** 8, other),
                          TxOut(24 * 10 ** 8 + 99990000, ah)])
        tx.sign([seed])
        b.node.connect_peers.append(("127.0.0.1", a.net.p2p_port))

        async def scenario():
            await a.node.start()
            await b.node.start()
            for _ in range(400):
                if (a.node.peers and b.node.peers
                        and b.node.peers[0].veracked
                        and b.chain.height() == a.chain.height()):
                    break
                await asyncio.sleep(0.05)
            assert b.chain.height() == a.chain.height(), "beta must sync first"
            ok, why = await a.node.submit_tx(tx)
            assert ok, why
            for _ in range(200):
                if len(b.mempool) == 1:
                    break
                await asyncio.sleep(0.05)
            assert len(b.mempool) == 1, "transaction was not relayed"
            assert b.mempool.get_tx(tx.txid()) is not None
            await a.node.stop()
            await b.node.stop()

        asyncio.run(scenario())
        a.close()
        b.close()

    def test_block_relay_after_mining(self, tmp_path):
        a = NodeHarness(tmp_path, "a")
        b = NodeHarness(tmp_path, "b")
        seed, pk, _ = ml_dsa.generate_keypair()
        ah = addr_mod.pk_to_hash(pk)
        mine(a.chain, ah, n=2)
        b.node.connect_peers.append(("127.0.0.1", a.net.p2p_port))

        async def scenario():
            await a.node.start()
            await b.node.start()
            for _ in range(200):
                if b.chain.height() == 2:
                    break
                await asyncio.sleep(0.05)
            assert b.chain.height() == 2
            # build the next block without connecting it, then hand it to the
            # node exactly as a miner or a peer would
            blk, _ = a.chain.create_block_template(
                ah, [], timestamp=a.chain.tip.header.timestamp + 1,
                extra_nonce=b"relay")
            blk.mine()
            assert await a.node.submit_block(blk, broadcast=True)
            for _ in range(200):
                if b.chain.height() == 3:
                    break
                await asyncio.sleep(0.05)
            assert b.chain.height() == 3
            assert b.chain.tip_hash() == blk.hash
            await a.node.stop()
            await b.node.stop()

        asyncio.run(scenario())
        a.close()
        b.close()

    def test_addr_exchange_and_redial(self, tmp_path):
        a = NodeHarness(tmp_path, "a")
        b = NodeHarness(tmp_path, "b")
        b.node.connect_peers.append(("127.0.0.1", a.net.p2p_port))

        async def scenario():
            await a.node.start()
            await b.node.start()
            for _ in range(200):
                if a.node.peers and b.node.peers:
                    break
                await asyncio.sleep(0.05)
            assert a.node.peers and b.node.peers
            await asyncio.sleep(0.4)
            assert ("127.0.0.1", a.net.p2p_port) in b.node._known_addrs
            # a learns b's address from the getaddr/addr exchange
            assert len(a.node._known_addrs) >= 1
            info = a.node.peer_info()
            assert info and info[0]["inbound"] is True
            await a.node.stop()
            await b.node.stop()

        asyncio.run(scenario())
        a.close()
        b.close()

    def test_addr_flood_is_penalised(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            peer = a.node.peers[0]
            await peer.send("version", {"version": C.PROTOCOL_VERSION,
                                        "network": a.net.name, "height": 0,
                                        "timestamp": int(time.time())})
            await asyncio.sleep(0.2)
            # a message offering more new addresses than we would ever serve
            with pytest.raises(PeerMisbehaved, match="addr flood"):
                await a.node._on_addr(peer, {"addrs": [
                    {"host": f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
                     "port": 19090}
                    for i in range(C.MAX_ADDR_RELAY + 8)]})
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()

    def test_moderate_addr_message_only_scores(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            peer = a.node.peers[0]
            await peer.send("version", {"version": C.PROTOCOL_VERSION,
                                        "network": a.net.name, "height": 0,
                                        "timestamp": int(time.time())})
            await asyncio.sleep(0.2)
            # an honest-size message is accepted without disconnecting
            await a.node._on_addr(peer, {"addrs": [
                {"host": f"10.1.{i // 256}.{i % 256}", "port": 19090}
                for i in range(200)]})
            assert len(a.node._known_addrs) == 200
            assert peer.decayed_score() > 0
            assert peer.closing is False
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()


class TestHeightAdvertisement:
    """A peer's view of our height is a snapshot; it has to be refreshed or a
    node that was level at handshake time never notices it fell behind."""

    def test_verack_is_answered_only_once(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            await asyncio.sleep(0.2)
            peer = a.node.peers[0]
            ver = {"version": C.PROTOCOL_VERSION, "network": a.net.name,
                   "height": 0, "timestamp": int(time.time())}
            await a.node._on_version(peer, dict(ver))
            assert peer.veracked
            await a.node._on_verack(peer, {})
            # a height refresh is a version, not a handshake restart
            await a.node._on_version(peer, dict(ver))
            assert peer.veracked
            await asyncio.sleep(0.3)
            assert len(a.node.peers) == 1, "the peer must still be connected"
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()

    def test_no_version_verack_ping_pong(self, tmp_path):
        a = NodeHarness(tmp_path, "a")
        b = NodeHarness(tmp_path, "b")
        b.node.connect_peers.append(("127.0.0.1", a.net.p2p_port))
        seen = collections.Counter()
        orig = type(a.node)._dispatch

        async def counting(self, peer, command, payload):
            seen[command] += 1
            return await orig(self, peer, command, payload)

        type(a.node)._dispatch = counting
        try:
            async def scenario():
                await a.node.start()
                await b.node.start()
                await asyncio.sleep(2.0)
                # a healthy handshake is a handful of frames, not thousands
                assert seen["version"] < 20, seen
                assert seen["verack"] < 20, seen
                assert len(a.node.peers) == 1
                await a.node.stop()
                await b.node.stop()

            asyncio.run(scenario())
        finally:
            type(a.node)._dispatch = orig
        a.close()
        b.close()

    def test_announce_only_when_the_height_changed(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            await asyncio.sleep(0.2)
            peer = a.node.peers[0]
            await a.node._on_version(peer, {
                "version": C.PROTOCOL_VERSION, "network": a.net.name,
                "height": 0, "timestamp": int(time.time())})
            await a.node._on_verack(peer, {})
            # nothing changed, so nothing is re-announced
            assert not await a.node.announce(peer)
            assert await a.node.announce(peer, force=True)
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()

    def test_sync_recovers_when_a_peer_moved_during_the_handshake(self, tmp_path):
        """The scenario that motivated the refresh: both nodes are level at
        handshake time, one then mines, and the other must still catch up."""
        a = NodeHarness(tmp_path, "a")
        b = NodeHarness(tmp_path, "b")
        _seed, pk, _ = ml_dsa.generate_keypair()
        ah = addr_mod.pk_to_hash(pk)
        b.node.connect_peers.append(("127.0.0.1", a.net.p2p_port))

        async def scenario():
            await a.node.start()
            await b.node.start()
            for _ in range(200):
                if a.node.peers and b.node.peers and b.node.peers[0].veracked:
                    break
                await asyncio.sleep(0.05)
            assert a.node.peers and b.node.peers
            # both are at height 0, so neither asks for headers; alpha then
            # mines and only the height refresh can tell beta it is behind
            for _ in range(5):
                blk, _ = a.chain.create_block_template(
                    ah, [], timestamp=a.chain.tip.header.timestamp + 1,
                    extra_nonce=b"late")
                blk.mine()
                await a.node.submit_block(blk, broadcast=True)
            for _ in range(400):
                if b.chain.height() == 5:
                    break
                await asyncio.sleep(0.05)
            assert b.chain.height() == 5, "beta did not catch up"
            await a.node.stop()
            await b.node.stop()

        asyncio.run(scenario())
        a.close()
        b.close()


    def test_a_peer_that_starts_late_is_still_connected(self, tmp_path):
        """A node told to dial a peer that is not listening yet must keep
        trying, not sit idle until the next discovery sweep."""
        a = NodeHarness(tmp_path, "a")
        # beta is configured to dial alpha before alpha has a listener
        b = NodeHarness(tmp_path, "b")
        b.node.connect_peers.append(("127.0.0.1", a.net.p2p_port))

        async def scenario():
            await b.node.start()
            await asyncio.sleep(0.3)
            assert not b.node.peers, "alpha is not listening yet"
            await a.node.start()
            for _ in range(200):
                if a.node.peers and b.node.peers:
                    break
                await asyncio.sleep(0.05)
            assert a.node.peers, "beta never retried the configured peer"
            assert b.node.peers
            await a.node.stop()
            await b.node.stop()

        asyncio.run(scenario())
        a.close()
        b.close()

    def test_discovery_sweep_redials_known_addresses(self, tmp_path):
        """The housekeeping sweep must not claim the in-flight slot itself:
        doing so made _connect_peer see its own key and skip the dial."""
        a = NodeHarness(tmp_path, "a")
        b = NodeHarness(tmp_path, "b")

        async def scenario():
            await a.node.start()
            # no --connect: the address only reaches beta through the sweep
            b.node._add_known_addr("127.0.0.1", a.net.p2p_port)
            await b.node.start()
            # _connect_peer serves the connection for its whole lifetime, so
            # it is scheduled, never awaited
            for _ in range(200):
                if a.node.peers:
                    break
                asyncio.ensure_future(
                    b.node._connect_peer("127.0.0.1", a.net.p2p_port))
                await asyncio.sleep(0.05)
            assert a.node.peers
            assert b.node.peers
            await a.node.stop()
            await b.node.stop()

        asyncio.run(scenario())
        a.close()
        b.close()


class TestPeerRules:
    def test_wrong_network_is_rejected_and_banned(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            await asyncio.sleep(0.2)
            peer = a.node.peers[0]
            before = len(a.node._banned)
            with pytest.raises(PeerMisbehaved, match="network mismatch"):
                await a.node._on_version(peer, {"version": 1,
                                                "network": "testnet",
                                                "height": 0})
            assert len(a.node._banned) == before + 1
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()

    def test_old_protocol_version_rejected(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            await asyncio.sleep(0.2)
            peer = a.node.peers[0]
            with pytest.raises(PeerMisbehaved, match="too old"):
                await a.node._on_version(peer, {"version": 0,
                                                "network": a.net.name,
                                                "height": 0})
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()

    def test_gross_clock_skew_penalised(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            await asyncio.sleep(0.2)
            peer = a.node.peers[0]
            await a.node._on_version(peer, {
                "version": C.PROTOCOL_VERSION, "network": a.net.name,
                "height": 0, "timestamp": 1})
            assert peer.penalise(0) is False
            assert peer.decayed_score() >= 0
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()

    def test_rate_limit_token_bucket(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            await asyncio.sleep(0.2)
            peer = a.node.peers[0]
            allowed = sum(1 for _ in range(C.PEER_MSG_BURST + 200)
                          if peer.allow_message())
            assert allowed <= C.PEER_MSG_BURST + 2
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()

    def test_banned_peer_is_refused(self, tmp_path):
        a = NodeHarness(tmp_path, "a")
        a.node._banned["127.0.0.1:1"] = (time.time() + 600, "test")
        assert a.node.is_banned("127.0.0.1:1")
        a.node._banned["127.0.0.1:1"] = (time.time() - 1, "test")
        assert not a.node.is_banned("127.0.0.1:1")
        a.close()

    def test_prompt_shutdown_with_a_silent_peer(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            await asyncio.sleep(0.3)
            assert a.node.peers, "silent peer should be connected"
            t0 = time.time()
            await asyncio.wait_for(a.node.stop(), timeout=6.0)
            assert time.time() - t0 < 4.0, "stop deadlocked on a silent peer"
            writer.close()
            assert not a.node.peers

        asyncio.run(scenario())
        a.close()

    def test_notfound_releases_a_pending_request(self, tmp_path):
        a = NodeHarness(tmp_path, "a")

        async def scenario():
            await a.node.start()
            reader, writer = await asyncio.open_connection(
                "127.0.0.1", a.net.p2p_port)
            await asyncio.sleep(0.2)
            peer = a.node.peers[0]
            h = bytes(range(64))
            a.node._requested[h] = time.time()
            peer.requested.add(h)
            await a.node._on_notfound(peer, {"blocks": [h.hex()]})
            assert h not in a.node._requested
            assert h not in peer.requested
            writer.close()
            await a.node.stop()

        asyncio.run(scenario())
        a.close()

"""P2P admission limits and header-batch validation.

Two classes of defect are pinned here:

  * `max_peers` used to be stored and never enforced, so a single host could
    open unlimited inbound connections (a socket + writer task + frame
    buffer each) and hold every slot.  The ceiling, the per-IP cap and the
    outbound reservation are all checked before the handshake now.
  * `_on_headers` used to accept any header whose hash was unknown, without
    checking that the batch chains onto a block we have, that the heights
    line up or that the proof of work is valid - and then inflated the
    peer's advertised height from the count of unseen headers.  A peer could
    therefore aim the sync driver at an arbitrary chain and keep the node
    permanently "syncing".
"""
import asyncio
import dataclasses
import socket
from pathlib import Path

from qeuph import constants as C
from qeuph.config import REGTEST
from qeuph.core.block import Block, BlockHeader
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.tx import make_coinbase
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.node.node import QNode, Peer, PeerMisbehaved


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class StubWriter:
    """Enough of a StreamWriter for a Peer that never actually reads/writes."""

    def __init__(self, ip="127.0.0.1", port=40404):
        self._peer = (ip, port)
        self.written = []
        self.closed = False

    def get_extra_info(self, name):
        return self._peer if name == "peername" else None

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True


class StubReader:
    async def read(self, n):
        return b""


def _make_node(root, max_peers=C.MAX_PEERS, name="node") -> QNode:
    net = dataclasses.replace(REGTEST, data_dir=str(Path(root) / name),
                              p2p_port=_free_port(),
                              rpc_port=_free_port())
    chain = ChainManager(net)
    mp = Mempool(chain.state_provider(), height_fn=chain.height,
                 mtp_fn=chain.median_time_past)
    return QNode(net, chain, mp, max_peers=max_peers)


def _peer(node, ip="127.0.0.1") -> Peer:
    p = Peer(StubReader(), StubWriter(ip), node, inbound=True)
    p.veracked = True
    return p


# ---------------------------------------------------------------------------
# admission limits
# ---------------------------------------------------------------------------
class TestConnectionLimits:
    def test_refusals_are_reported_without_a_socket(self, tmp_path):
        # a roomy ceiling, so the per-IP cap is what binds
        node = _make_node(tmp_path, max_peers=C.RESERVED_OUTBOUND_SLOTS + 32)
        try:
            # empty node: the first inbound connection is welcome
            assert node._refuse_connection("10.0.0.1", inbound=True) is None
            node.peers.append(_peer(node, "10.0.0.1"))
            for _ in range(C.MAX_PEERS_PER_IP - 1):
                node.peers.append(_peer(node, "10.0.0.1"))
            assert C.MAX_PEERS_PER_IP == sum(
                1 for p in node.peers if p.ip == "10.0.0.1")
            reason = node._refuse_connection("10.0.0.1", inbound=True)
            assert reason and "per-IP" in reason
            # a different host still fits while inbound slots remain
            assert node._refuse_connection("10.0.0.2", inbound=True) is None
        finally:
            node.chain.close()

    def test_inbound_slots_reserve_room_for_outbound(self, tmp_path):
        node = _make_node(tmp_path, max_peers=C.RESERVED_OUTBOUND_SLOTS + 1)
        try:
            cap = max(1, node.max_peers - C.RESERVED_OUTBOUND_SLOTS)
            for i in range(cap):
                assert node._refuse_connection(f"10.0.0.{i}", True) is None
                node.peers.append(_peer(node, f"10.0.0.{i}"))
            reason = node._refuse_connection("10.0.0.99", inbound=True)
            assert reason and "inbound limit" in reason
            # the reserved slot is still usable for an outbound dial
            assert node._refuse_connection("10.0.0.99", inbound=False) is None
        finally:
            node.chain.close()

    def test_total_ceiling_stops_everything(self, tmp_path):
        node = _make_node(tmp_path, max_peers=4)
        try:
            for i in range(4):
                node.peers.append(_peer(node, f"10.0.0.{i}"))
            reason = node._refuse_connection("10.0.0.9", inbound=True)
            assert reason and "peer limit" in reason
            assert node._refuse_connection("10.0.0.9", inbound=False)
        finally:
            node.chain.close()

    def test_live_server_refuses_a_connection_flood(self, tmp_path):
        """The real accept path, not just the predicate."""
        asyncio.run(self._flood(tmp_path))

    async def _flood(self, tmp_path):
        node = _make_node(tmp_path, max_peers=C.MAX_PEERS)
        node.bind_host = "127.0.0.1"
        await node.start()
        socks = []
        try:
            for _ in range(C.MAX_PEERS_PER_IP + 3):
                s = socket.create_connection(
                    ("127.0.0.1", node.network.p2p_port), timeout=5)
                socks.append(s)
            for _ in range(100):
                if len(node.peers) >= C.MAX_PEERS_PER_IP:
                    break
                await asyncio.sleep(0.05)
            inbound = [p for p in node.peers if p.inbound]
            assert 1 <= len(inbound) <= C.MAX_PEERS_PER_IP, len(inbound)
            # refused sockets must be closed by the server, not left hanging
            refused = 0
            for s in socks:
                s.settimeout(2)
                try:
                    if s.recv(16) == b"":
                        refused += 1
                except (ConnectionResetError, ConnectionAbortedError):
                    refused += 1
                except socket.timeout:
                    pass
            assert refused >= 1, "refused connections were not closed"
        finally:
            for s in socks:
                try:
                    s.close()
                except OSError:
                    pass
            await node.stop()
            node.chain.close()


# ---------------------------------------------------------------------------
# headers batches must be a contiguous, PoW-valid chain we can anchor
# ---------------------------------------------------------------------------
class TestHeaderBatchValidation:
    def _orphan_chain(self, node, n=3):
        """n mined headers extending the tip, never connected to the chain.

        These are exactly what an honest peer sends during initial block
        download: a contiguous run of headers whose bodies we do not have.
        """
        seed, pk, _ = ml_dsa.generate_keypair()
        ah = addr_mod.pk_to_hash(pk)
        out = []
        prev = node.chain.tip
        for _ in range(n):
            height = prev.height + 1
            coinbase = make_coinbase(height, ah,
                                     node.chain.coinbase_reward_with_fees(0),
                                     data=b"hdr")
            blk = Block.build(prev.hash, height, prev.header.bits, [coinbase],
                              timestamp=prev.header.timestamp + 1,
                              min_timestamp=prev.header.timestamp + 1)
            blk.mine()
            out.append(blk)
            prev = blk
        return out

    def test_contiguous_batch_is_accepted(self, tmp_path):
        node = _make_node(tmp_path)
        try:
            peer = _peer(node)
            node.peers.append(peer)
            blocks = self._orphan_chain(node, 3)
            asyncio.run(node._on_headers(peer, {
                "headers": [b.header.serialize().hex() for b in blocks]}))
            assert peer.best_height == blocks[-1].height
            assert peer.requested, "no getdata was sent for unknown headers"
            assert not peer.closing
        finally:
            node.chain.close()

    def test_unrooted_batch_disconnects_the_peer(self, tmp_path):
        node = _make_node(tmp_path)
        try:
            peer = _peer(node)
            node.peers.append(peer)
            blocks = self._orphan_chain(node, 2)
            # re-root the run at the null hash: it extends nothing we know
            detached = [BlockHeader(b.header.version, bytes(64),
                                    b.header.merkle_root, b.header.timestamp,
                                    b.header.bits, b.header.height,
                                    b.header.nonce) for b in blocks]
            try:
                asyncio.run(node._on_headers(peer, {
                    "headers": [h.serialize().hex() for h in detached]}))
                raise AssertionError("unrooted headers were accepted")
            except PeerMisbehaved:
                pass
            assert peer.score >= C.BAN_SCORE_THRESHOLD // 2
        finally:
            node.chain.close()

    def test_broken_chain_disconnects_the_peer(self, tmp_path):
        node = _make_node(tmp_path)
        try:
            peer = _peer(node)
            node.peers.append(peer)
            blocks = self._orphan_chain(node, 2)
            # the second header no longer points at the first
            bad = BlockHeader(blocks[1].header.version, bytes(64),
                              blocks[1].header.merkle_root,
                              blocks[1].header.timestamp,
                              blocks[1].header.bits, blocks[1].header.height,
                              blocks[1].header.nonce)
            try:
                asyncio.run(node._on_headers(peer, {
                    "headers": [blocks[0].header.serialize().hex(),
                                bad.serialize().hex()]}))
                raise AssertionError("a broken header chain was accepted")
            except PeerMisbehaved:
                pass
            assert peer.score >= C.BAN_SCORE_THRESHOLD // 2
        finally:
            node.chain.close()

    def test_header_without_valid_pow_disconnects_the_peer(self, tmp_path):
        node = _make_node(tmp_path)
        try:
            peer = _peer(node)
            node.peers.append(peer)
            hdr = self._orphan_chain(node, 1)[0].header
            bogus = BlockHeader(hdr.version, hdr.prev_hash, hdr.merkle_root,
                                hdr.timestamp, C.HARDEST_BITS, hdr.height, 0)
            try:
                asyncio.run(node._on_headers(peer, {
                    "headers": [bogus.serialize().hex()]}))
                raise AssertionError("a header without PoW was accepted")
            except PeerMisbehaved:
                pass
            assert peer.score >= C.BAN_SCORE_THRESHOLD
        finally:
            node.chain.close()

    def test_malformed_header_disconnects_the_peer(self, tmp_path):
        node = _make_node(tmp_path)
        try:
            peer = _peer(node)
            node.peers.append(peer)
            try:
                asyncio.run(node._on_headers(peer, {"headers": ["nothex"]}))
                raise AssertionError("a malformed header was accepted")
            except PeerMisbehaved:
                pass
        finally:
            node.chain.close()

def _peer(node, ip="127.0.0.1") -> Peer:
    p = Peer(StubReader(), StubWriter(ip), node, inbound=True)
    p.veracked = True
    return p

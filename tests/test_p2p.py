"""Two-node P2P test: block + tx relay over a real TCP connection."""
import asyncio
import shutil
import time

import pytest

from qeuph.config import REGTEST
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.node.node import QNode

TMP1 = "/tmp/qeuph-tests-p2p-a"
TMP2 = "/tmp/qeuph-tests-p2p-b"


import socket

def _get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _run_scenario():
    p1 = _get_free_port()
    r1 = _get_free_port()
    p2 = _get_free_port()
    r2 = _get_free_port()

    import dataclasses
    net = dataclasses.replace(REGTEST, data_dir=TMP1, p2p_port=p1, rpc_port=r1)

    chain1 = ChainManager(net)
    mp1 = Mempool(chain1.state, height_fn=chain1.height)
    node1 = QNode(net, chain1, mp1)
    await node1.start()

    # second node: separate profile (own listen port + storage), same genesis
    net2 = dataclasses.replace(net, data_dir=TMP2, p2p_port=p2, rpc_port=r2)
    chain2 = ChainManager(net2)
    mp2 = Mempool(chain2.state, height_fn=chain2.height)
    node2 = QNode(net2, chain2, mp2, connect_peers=[("127.0.0.1", p1)])
    await node2.start()

    try:
        # wait for handshake
        for _ in range(50):
            if node1.peers and node2.peers:
                break
            await asyncio.sleep(0.1)
        assert node1.peers and node2.peers, "peers did not connect"

        # node1 mines blocks; node2 should receive them via relay
        seed, pk, _ = ml_dsa.generate_keypair()
        ah = addr_mod.pk_to_hash(pk)
        mined = []
        for _ in range(3):
            b, _ = chain1.create_block_template(ah, [])
            b.mine()
            await node1.submit_block(b, broadcast=True)
            mined.append(b)
        for _ in range(100):
            if chain2.height() >= 3:
                break
            await asyncio.sleep(0.05)
        assert chain2.height() == 3, f"node2 height {chain2.height()}"
        assert chain2.tip_hash() == chain1.tip_hash()

        # tx relay: node2 accepts a tx, node1 must see it in its mempool
        other = addr_mod.pk_to_hash(ml_dsa.generate_keypair()[1])
        cb_txid = mined[0].transactions[0].txid()
        # mature the coinbase on chain1 (mine 101 empty blocks quickly)
        for _ in range(101):
            b, _ = chain1.create_block_template(ah, [])
            b.mine()
            await node1.submit_block(b, broadcast=True)
        for _ in range(200):
            if chain2.height() >= 104:
                break
            await asyncio.sleep(0.05)
        assert chain2.height() >= 104

        tx = Transaction([TxIn(cb_txid, 0, 1)], [TxOut(10**9, other)])
        tx.sign([seed])
        accepted, reason = await node2.submit_tx(tx, broadcast=True)
        assert accepted, reason
        for _ in range(100):
            if node1.mempool.get_tx(tx.txid()) is not None:
                break
            await asyncio.sleep(0.05)
        got = node1.mempool.get_tx(tx.txid())
        assert got is not None and got.serialize() == tx.serialize()
    finally:
        await node1.stop()
        await node2.stop()
        if chain1.store:
            chain1.store.close()
        if chain2.store:
            chain2.store.close()


class TestP2P:
    def test_relay(self):
        shutil.rmtree(TMP1, ignore_errors=True)
        shutil.rmtree(TMP2, ignore_errors=True)
        asyncio.run(_run_scenario())

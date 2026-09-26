"""End-to-end integration test: daemon + RPC + miner + wallet on regtest.

Spins up the real Daemon (P2P listener, JSON-RPC, solo miner) on the
regtest network, mines coinbase-matured blocks, creates a wallet, and
executes a signed P2P-style transfer through the RPC surface.
"""
import json
import shutil
import threading
import time
import urllib.request

import pytest

from qeuph import constants as C
from qeuph.config import REGTEST

TMP = "/tmp/qeuph-tests-integration"
REGTEST.data_dir = TMP
REGTEST.p2p_port = 39777        # avoid clashes with anything else
REGTEST.rpc_port = 39778
RPC = f"http://127.0.0.1:{REGTEST.rpc_port}/"


@pytest.fixture(scope="module")
def daemon():
    shutil.rmtree(TMP, ignore_errors=True)
    net = REGTEST
    # re-apply: other test modules mutate the shared REGTEST object
    net.data_dir = TMP
    net.p2p_port = 39777
    net.rpc_port = 39778

    from qeuph.main import Daemon
    d = Daemon(net)
    holder = {}

    def run():
        import asyncio
        import traceback
        try:
            holder["loop"] = asyncio.new_event_loop()
            asyncio.set_event_loop(holder["loop"])
            holder["loop"].run_until_complete(d.run())
        except Exception:
            holder["error"] = traceback.format_exc()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    # wait for RPC
    for _ in range(100):
        if "error" in holder:
            pytest.fail("daemon crashed:\n" + holder["error"])
        try:
            rpc("getblockchaininfo")
            break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("daemon RPC did not come up")
    yield d
    rpc("stop")
    time.sleep(0.5)


def rpc(method, params=None):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                          "params": params or {}}).encode()
    req = urllib.request.Request(RPC, data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        doc = json.loads(resp.read())
    if doc.get("error"):
        raise RuntimeError(str(doc["error"]))
    return doc["result"]


class TestIntegration:
    def test_chain_info(self, daemon):
        info = rpc("getblockchaininfo")
        assert info["chain"] == "regtest"
        assert info["height"] == 0
        assert info["reward"] == 50 * C.QUPHI_PER_QUH

    def test_mine_maturity_and_transfer(self, daemon):
        # wallet for the recipient
        from qeuph.wallet import Wallet
        w = Wallet.create(hrp="rquh", network="regtest")
        recipient = w.address_at(0)

        # miner wallet (payout address)
        mw = Wallet.create(hrp="rquh", network="regtest")
        miner_addr = mw.address_at(0)

        rpc("startminer", {"address": miner_addr})
        deadline = time.time() + 120
        while time.time() < deadline:
            info = rpc("getblockchaininfo")
            if info["height"] >= 102:
                break
            time.sleep(0.2)
        rpc("stopminer")
        info = rpc("getblockchaininfo")
        assert info["height"] >= 102, info

        bal = rpc("getbalance", {"address": miner_addr})
        assert bal["balance"] >= 101 * 50 * C.QUPHI_PER_QUH
        matured = bal["matured_balance"]
        assert matured >= 50 * C.QUPHI_PER_QUH   # coinbase of block 1 matured

        # send 12.5 QUH from miner address 0 to recipient
        tx = mw.build_transaction(
            0, [(recipient, round(12.5 * C.QUPHI_PER_QUH))],
            fee=round(0.01 * C.QUPHI_PER_QUH), rpc_url=RPC)
        txid = mw.send_transaction(tx, RPC)
        mem = rpc("getmempoolinfo")
        assert mem["count"] == 1

        # mine a block to confirm
        rpc("startminer", {"address": miner_addr})
        deadline = time.time() + 60
        while time.time() < deadline:
            if rpc("getmempoolinfo")["count"] == 0:
                break
            time.sleep(0.1)
        rpc("stopminer")

        got = rpc("getbalance", {"address": recipient})
        assert got["balance"] == round(12.5 * C.QUPHI_PER_QUH)
        nonce = rpc("getnonce", {"address": miner_addr})
        assert nonce["nonce"] == 1

        # transaction is queryable
        txinfo = rpc("gettransaction", {"txid": txid})
        assert txinfo["height"] >= 103

        # the recipient can spend onward (nonce 1 for the new address)
        tx2 = w.build_transaction(
            0, [(miner_addr, round(5 * C.QUPHI_PER_QUH))],
            fee=round(0.01 * C.QUPHI_PER_QUH), rpc_url=RPC)
        w.send_transaction(tx2, RPC)
        rpc("startminer", {"address": miner_addr})
        deadline = time.time() + 60
        while time.time() < deadline:
            if rpc("getmempoolinfo")["count"] == 0:
                break
            time.sleep(0.1)
        rpc("stopminer")
        got2 = rpc("getbalance", {"address": recipient})
        assert got2["balance"] == round(7.49 * C.QUPHI_PER_QUH)

    def test_block_and_reward_queries(self, daemon):
        b0 = rpc("getblock", {"height": 0})
        assert b0["height"] == 0
        assert "transactions" not in b0 or b0["tx_count"] == 1
        info = rpc("getblockchaininfo")
        assert info["difficulty"] > 0
        r = rpc("getrewardinfo", {"height": 210_000})
        assert r["reward"] == 3_333_333_333

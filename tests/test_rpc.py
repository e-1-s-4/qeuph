"""JSON-RPC surface: protocol conformance, auth, batching and method set."""
from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from qeuph import constants as C
from qeuph.config import REGTEST
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.network.rpc import (E_INVALID_REQUEST, E_INVALID_PARAMS,
                               E_METHOD_NOT_FOUND, E_PARSE, E_TX_ERROR,
                               RPCService)
from qeuph.node.node import QNode
from qeuph.services.miner import SoloMiner

from .conftest import free_port, mine


class RpcHarness:
    """A real node with a real loopback JSON-RPC listener."""

    def __init__(self, network, user=None, password=None):
        self.chain = ChainManager(network)
        self.mempool = Mempool(self.chain.state_provider(),
                               fee_rate=C.MIN_RELAY_FEE_RATE,
                               height_fn=self.chain.height,
                               mtp_fn=self.chain.median_time_past)
        self.node = QNode(network, self.chain, self.mempool)
        self.miner = SoloMiner(self.node)
        self.port = free_port()
        self.rpc = RPCService(self.node, self.miner, "127.0.0.1", self.port,
                              self._stop, rpc_user=user, rpc_password=password)
        self._evt = threading.Event()
        self._loop = None
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        for _ in range(200):
            if self.rpc._server is not None:
                break
            time.sleep(0.02)
        self.url = f"http://127.0.0.1:{self.port}/"
        self.auth = None
        if user is not None or password is not None:
            self.auth = base64.b64encode(
                f"{user or ''}:{password or ''}".encode()).decode()

    def submit_coro_block(self, block):
        """Connect a block through the node (as a peer would) and wait."""
        import asyncio
        fut = asyncio.run_coroutine_threadsafe(
            self.node.submit_block(block, broadcast=True), self._loop)
        return fut.result(timeout=60)

    def _stop(self):
        self._evt.set()

    def _run(self):
        import asyncio
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self.rpc.start_background(self._loop)
        self._loop.run_forever()

    def call(self, method, params=None, auth=True, raw=None, timeout=30):
        body = raw if raw is not None else json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method,
             "params": params or {}}).encode()
        headers = {"Content-Type": "application/json"}
        if auth and self.auth:
            headers["Authorization"] = "Basic " + self.auth
        req = urllib.request.Request(self.url, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())

    def close(self):
        self._evt.set()
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        self.rpc.stop()
        self.miner.stop()
        self.chain.close()


@pytest.fixture()
def rpc(tmp_path):
    h = RpcHarness(REGTEST.with_(data_dir=str(tmp_path / "c"),
                                p2p_port=free_port(), rpc_port=free_port()))
    try:
        yield h
    finally:
        h.close()


class TestProtocol:
    def test_genesis_info(self, rpc):
        info = rpc.call("getblockchaininfo")["result"]
        assert info["chain"] == "regtest"
        assert info["height"] == 0
        assert info["reward"] == 50 * C.QUPHI_PER_QUH
        assert info["max_supply"] == C.MAX_SUPPLY_QUH
        assert info["chainwork"].startswith("0x")

    def test_error_is_jsonrpc_object_with_http_200(self, rpc):
        doc = rpc.call("nosuchmethod")
        assert doc["error"]["code"] == E_METHOD_NOT_FOUND
        assert "nosuchmethod" in doc["error"]["message"]
        assert doc["jsonrpc"] == "2.0" and doc["id"] == 1
        assert "result" not in doc

    def test_invalid_request(self, rpc):
        # a batch of non-objects answers with one error per element
        doc = rpc.call(None, raw=json.dumps([1, 2, 3]).encode())
        assert isinstance(doc, list) and len(doc) == 3
        assert all(d["error"]["code"] == E_INVALID_REQUEST for d in doc)
        # a single non-object answers with one error object
        doc = rpc.call(None, raw=json.dumps(7).encode())
        assert doc["error"]["code"] == E_INVALID_REQUEST

    def test_parse_error(self, rpc):
        doc = rpc.call(None, raw=b"{not json")
        assert doc["error"]["code"] == E_PARSE

    def test_bad_jsonrpc_version(self, rpc):
        doc = rpc.call(None, raw=json.dumps(
            {"jsonrpc": "1.0", "id": 7, "method": "getblockcount"}).encode())
        assert doc["error"]["code"] == E_INVALID_REQUEST
        assert doc["id"] == 7

    def test_missing_method(self, rpc):
        doc = rpc.call(None, raw=json.dumps({"jsonrpc": "2.0", "id": 3}).encode())
        assert doc["error"]["code"] == E_INVALID_REQUEST

    def test_batch(self, rpc):
        batch = [{"jsonrpc": "2.0", "id": 1, "method": "getblockcount"},
                 {"jsonrpc": "2.0", "id": 2, "method": "getbestblockhash"},
                 {"jsonrpc": "2.0", "id": 3, "method": "bogus"}]
        out = rpc.call(None, raw=json.dumps(batch).encode())
        assert isinstance(out, list) and len(out) == 3
        assert out[0]["result"] == 0
        assert len(out[1]["result"]) == 128
        assert out[2]["error"]["code"] == E_METHOD_NOT_FOUND

    def test_empty_batch_rejected(self, rpc):
        out = rpc.call(None, raw=b"[]")
        assert out["error"]["code"] == E_INVALID_REQUEST

    def test_oversized_batch_rejected(self, rpc):
        batch = [{"jsonrpc": "2.0", "id": i, "method": "getblockcount"}
                 for i in range(64)]
        out = rpc.call(None, raw=json.dumps(batch).encode())
        assert out["error"]["code"] == E_INVALID_REQUEST

    def test_get_over_http(self, rpc):
        with urllib.request.urlopen(
                rpc.url + "?method=getblockcount&params=%7B%7D", timeout=20) as r:
            doc = json.loads(r.read())
        assert doc["result"] == 0

    def test_unknown_params_type(self, rpc):
        doc = rpc.call(None, raw=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "getblockcount",
             "params": 5}).encode())
        assert doc["error"]["code"] == E_INVALID_PARAMS


class TestAuth:
    @pytest.fixture()
    def secured(self, tmp_path):
        h = RpcHarness(REGTEST.with_(data_dir=str(tmp_path / "s"),
                                    p2p_port=free_port(), rpc_port=free_port()),
                       user="node", password="s3cret")
        try:
            yield h
        finally:
            h.close()

    def test_unauthenticated_call_refused(self, secured):
        with pytest.raises(urllib.error.HTTPError) as e:
            secured.call("getblockcount", auth=False)
        assert e.value.code == 401

    def test_authenticated_call_works(self, secured):
        assert secured.call("getblockcount")["result"] == 0

    def test_wrong_password_refused(self, secured):
        bad = base64.b64encode(b"node:wrong").decode()
        req = urllib.request.Request(
            secured.url, data=json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "getblockcount"}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Basic " + bad})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=20)
        assert e.value.code == 401

    def test_auth_required_flag(self, secured):
        assert secured.rpc.auth_required


class TestChainMethods:
    def test_block_queries(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        mine(rpc.chain, ah, n=3)
        assert rpc.call("getblockcount")["result"] == 3
        h1 = rpc.call("getblockhash", {"height": 1})["result"]
        assert len(h1) == 128
        b = rpc.call("getblock", {"hash": h1})["result"]
        assert b["height"] == 1
        assert b["confirmations"] == 3
        assert b["tx_count"] == 1
        b2 = rpc.call("getblock", {"height": 2, "verbose": False})["result"]
        assert isinstance(b2, str) and len(b2) // 2 > 168
        st = rpc.call("getblockstats", {"height": 1})["result"]
        assert st["height"] == 1
        assert st["subsidy"] == 50 * C.QUPHI_PER_QUH
        assert rpc.call("getdifficulty")["result"] > 0
        assert rpc.call("getbestblockhash")["result"] == \
            rpc.call("getblockchaininfo")["result"]["best"]

    def test_unknown_block(self, rpc):
        assert rpc.call("getblock", {"height": 99})["error"]["code"] == -32030
        assert rpc.call("getblockhash", {"height": 99})["error"]

    def test_bad_hash(self, rpc):
        assert rpc.call("getblock", {"hash": "zz"})["error"]["code"] == \
            E_INVALID_PARAMS

    def test_reward_info(self, rpc):
        r = rpc.call("getrewardinfo", {"height": 210_000})["result"]
        assert r["reward"] == 3_333_333_333
        assert r["epoch"] == 1
        assert r["next_epoch_height"] == 420_000
        assert r["cap"] == C.MAX_SUPPLY
        assert r["final_reward_height"] == 11_130_000
        assert r["total_emitted"] > 0
        r0 = rpc.call("getrewardinfo", {"height": 0})["result"]
        assert r0["total_emitted"] == 50 * C.QUPHI_PER_QUH

    def test_chaintips(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        mine(rpc.chain, ah, n=4)
        tips = rpc.call("getchaintips")["result"]
        assert tips["count"] >= 1
        active = [t for t in tips["tips"] if t["status"] == "active"]
        assert active and active[0]["height"] == 4

    def test_nodeinfo_and_uptime(self, rpc):
        n = rpc.call("getnodeinfo")["result"]
        assert n["height"] == 0 and n["synced"] is not None
        assert n["rpc_calls"] > 0
        assert rpc.call("uptime")["result"] >= 0

    def test_networkinfo(self, rpc):
        n = rpc.call("getnetworkinfo")["result"]
        assert n["network"] == "regtest"
        assert n["hrp"] == "rquh"
        assert n["genesis_hash"] == rpc.chain.genesis.hash.hex()
        assert n["coinbase_maturity"] == 100
        assert n["dust_threshold"] == C.DUST_THRESHOLD
        assert n["block_time"] == 300


class TestAddressMethods:
    def test_validate_and_balance(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        addr = addr_mod.hash_to_address(ah, rpc.node.network.hrp)
        v = rpc.call("validateaddress", {"address": addr})["result"]
        assert v["isvalid"] and v["addr_hash"] == ah.hex()
        bad = rpc.call("validateaddress", {"address": "nope"})["result"]
        assert not bad["isvalid"]
        info = rpc.call("getaddressinfo", {"address": addr})["result"]
        assert info["balance"] == 0 and info["nonce"] == 0
        b = rpc.call("getbalance", {"address": addr})["result"]
        assert b["balance"] == 0
        n = rpc.call("getnonce", {"address": addr})["result"]
        assert n["nonce"] == 0
        u = rpc.call("listunspent", {"address": addr})["result"]
        assert u == []

    def test_cross_network_address_rejected(self, rpc):
        from qeuph.crypto import ml_dsa as md
        _s, pk, _ = md.generate_keypair()
        mainnet_addr = addr_mod.pk_to_address(pk, "quh")
        doc = rpc.call("getbalance", {"address": mainnet_addr})
        assert doc["error"]["code"] == E_INVALID_PARAMS

    def test_missing_address(self, rpc):
        assert rpc.call("getbalance", {})["error"]["code"] == E_INVALID_PARAMS

    def test_balance_after_mining(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        mine(rpc.chain, ah, n=101)
        addr = addr_mod.hash_to_address(ah, rpc.node.network.hrp)
        b = rpc.call("getbalance", {"address": addr})["result"]
        assert b["balance"] == 101 * 50 * C.QUPHI_PER_QUH
        assert b["matured_balance"] == 50 * C.QUPHI_PER_QUH
        utxos = rpc.call("listutxos", {"address": addr})["result"]["utxos"]
        assert len(utxos) == 101
        # consensus maturity is `height - cb_height >= 100`, so at height 101
        # only the coinbase of block 1 is spendable - `mature` agrees with
        # `matured_only`, and `confirmations` is the display value (101)
        mature = [u for u in utxos if u["mature"]]
        assert len(mature) == 1
        assert mature[0]["confirmations"] == 101
        only_mature = rpc.call("listutxos", {"address": addr,
                                             "matured_only": True})["result"]
        assert len(only_mature["utxos"]) == len(mature)
        out = rpc.call("gettxout", {"txid": utxos[0]["txid"],
                                    "index": utxos[0]["index"]})["result"]
        assert out["coinbase"] and out["value"] == 50 * C.QUPHI_PER_QUH
        assert rpc.call("gettxout", {"txid": "00" * 64, "index": 0})["result"] \
            is None


class TestTransactionMethods:
    def _funded_wallet(self, rpc):
        from qeuph.wallet import Wallet
        w = Wallet.create(hrp=rpc.node.network.hrp, network="regtest")
        ah = addr_mod.address_to_hash(w.address_at(0), rpc.node.network.hrp)
        mine(rpc.chain, ah, n=101)
        return w, ah

    def test_send_and_query(self, rpc):
        w, ah = self._funded_wallet(rpc)
        to = Wallet_addr(rpc)
        # point the wallet at this harness' own UTXO/nonce view instead of a
        # separate daemon
        w.fetch_utxos = lambda addr, url, matured_only=True: [
            (bytes.fromhex(u["txid"]), u["index"], u["value"]) for u in
            rpc.call("listutxos", {"address": w.address_at(0),
                                   "matured_only": True})["result"]["utxos"]]
        w.fetch_nonce = lambda addr, url: rpc.call(
            "getnonce", {"address": addr})["result"]["nonce"]
        tx = w.build_transaction(0, [(to, 12 * 10 ** 8)], fee=10 ** 6,
                                 rpc_url="x")
        res = rpc.call("sendrawtransaction",
                       {"tx_hex": tx.serialize().hex()})["result"]
        assert res["accepted"] and res["txid"] == tx.txid().hex()
        assert rpc.call("getrawmempool")["result"] == [tx.txid().hex()]
        d = rpc.call("getrawtransaction",
                     {"txid": tx.txid().hex(), "verbose": True})["result"]
        assert d["txid"] == tx.txid().hex()
        got = rpc.call("gettransaction", {"txid": tx.txid().hex()})["result"]
        assert got["mempool"] is True
        # confirm it the way a node does, through the P2P submission path
        blk, _ = rpc.chain.create_block_template(ah, rpc.mempool.best_transactions(
            C.MAX_BLOCK_SIZE - 200_000))
        blk.mine()
        assert rpc.submit_coro_block(blk)
        got = rpc.call("gettransaction", {"txid": tx.txid().hex()})["result"]
        assert got["height"] == 102
        assert got["mempool"] is False
        assert got["confirmations"] == 1
        assert rpc.call("getrawmempool")["result"] == []

    def test_send_rejects_bad_hex(self, rpc):
        assert rpc.call("sendrawtransaction", {"hex": "zz"})["error"]

    def test_send_rejects_invalid_tx(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        mine(rpc.chain, ah, n=101)
        bogus = Transaction_bad(ah)
        doc = rpc.call("sendrawtransaction", {"hex": bogus})
        assert doc["error"]["code"] == E_TX_ERROR

    def test_decoderawtransaction(self, rpc, miner_keys):
        from qeuph.core.tx import Transaction
        seed, pk, _ = ml_dsa.generate_keypair()
        from qeuph.core.tx import TxIn, TxOut
        tx = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(5 * 10 ** 8, bytes(64))])
        tx.sign([seed])
        d = rpc.call("decoderawtransaction",
                     {"hex": tx.serialize().hex()})["result"]
        assert d["outputs"][0]["value_quh"] == 5.0
        assert d["inputs"][0]["signature"]
        assert d["size"] == tx.size()
        assert rpc.call("decoderawtransaction", {"hex": "00"})["error"]

    def test_createrawtransaction(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        addr = addr_mod.hash_to_address(ah, rpc.node.network.hrp)
        from qeuph.core.tx import Transaction
        raw = rpc.call("createrawtransaction", {
            "inputs": [{"txid": "11" * 64, "index": 0, "nonce": 4}],
            "outputs": [{addr: 1.5}],
            "locktime": 0})["result"]
        assert len(raw["hex"]) > 100 and len(raw["txid"]) == 128
        # createrawtransaction emits the canonical form with empty pubkey /
        # signature placeholders; decoderawtransaction accepts that shape and
        # flags it as unsigned, while the strict consensus parser would not
        d = rpc.call("decoderawtransaction", {"hex": raw["hex"]})["result"]
        assert d["unsigned"] is True
        assert d["inputs"][0]["txnonce"] == 4
        assert d["outputs"][0]["value_quh"] == 1.5
        with pytest.raises(ValueError):
            Transaction.deserialize(bytes.fromhex(raw["hex"]))
        assert rpc.call("createrawtransaction",
                        {"inputs": [], "outputs": {addr: 1}})["error"]

    def test_signrawtransaction_refuses(self, rpc):
        doc = rpc.call("signrawtransaction", {"hex": "00"})
        assert doc["error"]["code"] == -32030
        assert "wallet" in doc["error"]["message"]

    def test_mempool_info(self, rpc):
        m = rpc.call("getmempoolinfo")["result"]
        assert m["count"] == 0 and m["maxbytes"] == C.MAX_MEMPOOL_SIZE
        assert rpc.call("getmempool")["result"] == {"txids": []}
        assert rpc.call("getrawmempool")["result"] == []


class TestMiningMethods:
    def test_getblocktemplate(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        mine(rpc.chain, ah, n=2)
        t = rpc.call("getblocktemplate")["result"]
        assert t["height"] == 3
        assert t["previousblockhash"] == rpc.chain.tip_hash().hex()
        assert t["coinbasevalue"] == 50 * C.QUPHI_PER_QUH
        assert len(t["header_hex"]) == 336        # 168 bytes
        assert t["sizelimit"] == C.MAX_BLOCK_SIZE

    def test_generate(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        addr = addr_mod.hash_to_address(ah, rpc.node.network.hrp)
        r = rpc.call("generate", {"nblocks": 3, "address": addr})["result"]
        assert len(r["hashes"]) == 3
        assert rpc.call("getblockcount")["result"] == 3

    def test_generate_needs_address(self, rpc):
        assert rpc.call("generate", {"nblocks": 1})["error"]["code"] == \
            E_INVALID_PARAMS

    def test_generate_range(self, rpc):
        assert rpc.call("generate", {"nblocks": 0})["error"]
        assert rpc.call("generate", {"nblocks": 100000})["error"]

    def test_mining_lifecycle(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        addr = addr_mod.hash_to_address(ah, rpc.node.network.hrp)
        s = rpc.call("startminer", {"address": addr, "threads": 2})["result"]
        assert s["mining"] and s["threads"] == 2
        deadline = time.time() + 60
        while time.time() < deadline and rpc.call("getblockcount")["result"] < 3:
            time.sleep(0.1)
        rpc.call("stopminer")
        assert not rpc.call("getmininginfo")["result"]["mining"]
        assert rpc.call("getmininginfo")["result"]["blocks_mined"] >= 1

    def test_startminer_bad_address(self, rpc):
        assert rpc.call("startminer", {"address": "nope"})["error"][
            "code"] == E_INVALID_PARAMS


class TestAdminMethods:
    def test_help_lists_everything(self, rpc):
        h = rpc.call("help")["result"]
        for key in ("chain", "transactions", "mining", "mempool",
                    "wallet_and_address", "network", "admin"):
            assert key in h
        flat = {m for v in h.values() for m in v}
        for m in ("getblockchaininfo", "getblock", "gettransaction",
                  "sendrawtransaction", "startminer", "getbalance",
                  "validateaddress", "getpeerinfo", "stop", "rescan"):
            assert m in flat

    def test_rescan(self, rpc, miner_keys):
        seed, pk, ah = miner_keys
        mine(rpc.chain, ah, n=6)
        r = rpc.call("rescan")["result"]
        assert r["ok"] and r["checked"] == 6

    def test_savewallet_refuses(self, rpc):
        doc = rpc.call("savewallet", {"path": "/tmp/x.json"})
        assert doc["error"]["code"] == -32030
        assert "qeuph wallet" in doc["error"]["message"]

    def test_peerinfo(self, rpc):
        p = rpc.call("getpeerinfo")["result"]
        assert p["peers"] == [] and p["count"] == 0
        assert rpc.call("getconnectioncount")["result"] == 0


# helpers -----------------------------------------------------------------
def Wallet_addr(harness):
    _s, pk, _ = ml_dsa.generate_keypair()
    return addr_mod.pk_to_address(pk, harness.node.network.hrp)


def Transaction_bad(ah):
    from qeuph.core.tx import TxIn, TxOut, Transaction
    tx = Transaction([TxIn(bytes(64), 0, 1)], [TxOut(10 ** 8, ah)])
    tx.inputs[0].pubkey = bytes(ml_dsa.PK_SIZE)
    tx.inputs[0].signature = bytes(ml_dsa.SIG_SIZE)
    return tx.serialize().hex()

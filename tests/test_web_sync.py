"""Tests for the UI<->CLI sync layer added in the 2026 hardening pass.

Covers the four gaps that blocked "UI node joins a mesh of CLI nodes":

* P0-a  the dashboard Send route actually signs and broadcasts
* P0-b  the web-embedded node RUNS P2P (dials `--connect` peers, accepts
        inbound connections from CLI daemons) and syncs real blocks
* P0-c  remote-attach mode (`--embedded-node off --remote-rpc URL`) serves
        every explorer view from an external node's JSON-RPC
* P0-d  STATIC_DIRS no longer consults the repo root / cwd
* P1-b  no recovery phrase over HTTP, no wallet auto-create on GET
* P2-a  the P2P listener honours bind_host; web degrades on port clash
* P2-b  createrawtransaction converts JSON floats exactly (Decimal)
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from qeuph import constants as C
from qeuph.config import REGTEST
from qeuph.web.server import STATIC_DIRS, NodeManager, QeuphHttpHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rpc(url, method, params=None, timeout=60):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        doc = json.loads(r.read())
    if doc.get("error"):
        raise RuntimeError(f"{method}: {doc['error']}")
    return doc["result"]


class WebClient:
    def __init__(self, port):
        self.base = f"http://127.0.0.1:{port}"

    def get(self, path, timeout=60):
        with urllib.request.urlopen(self.base + path, timeout=timeout) as r:
            return json.loads(r.read())

    def raw(self, path, timeout=60):
        with urllib.request.urlopen(self.base + path, timeout=timeout) as r:
            return r.status, r.read().decode()

    def post(self, path, body, timeout=300):
        req = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())


class CliDaemon:
    """A real `qeuph node` subprocess, exactly as an operator would run it."""

    def __init__(self, root, name, network="regtest", connect=None,
                 mine=False):
        self.name = name
        self.p2p = free_port()
        self.rpc_port = free_port()
        self.url = f"http://127.0.0.1:{self.rpc_port}/"
        self.dir = os.path.join(root, name)
        argv = [sys.executable, "-m", "qeuph.cli.main", "node",
                "--network", network, "--data-dir", self.dir,
                "--p2p-port", str(self.p2p), "--rpc-port", str(self.rpc_port),
                "--p2p-host", "127.0.0.1"]
        if connect:
            argv += ["--connect", connect]
        self.log_path = os.path.join(root, f"{name}.log")
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(argv, cwd=ROOT, stdout=self.log,
                                     stderr=subprocess.STDOUT)

    def wait_ready(self, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError(f"{self.name} died:\n"
                                   f"{open(self.log_path).read()[-2000:]}")
            try:
                rpc(self.url, "getblockcount", timeout=2)
                return
            except Exception:
                time.sleep(0.15)
        raise RuntimeError(f"{self.name} RPC never came up")

    def stop(self):
        try:
            rpc(self.url, "stop", timeout=10)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


def _spin_web(node_manager):
    """Serve QeuphHttpHandler over a free port with the given NodeManager."""
    import qeuph.web.server as ws
    old_node, old_remote = ws.NODE, ws.REMOTE_RPC
    ws.NODE = node_manager
    ws.REMOTE_RPC = None
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), QeuphHttpHandler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return WebClient(port), srv, (old_node, old_remote)


def _teardown_web(srv, saved):
    import qeuph.web.server as ws
    srv.shutdown()
    srv.server_close()
    old_node, old_remote = saved
    ws.NODE, ws.REMOTE_RPC = old_node, old_remote


def _wait_until(fn, timeout=30.0, what="condition"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = fn()
        if last:
            return last
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {what} (last={last!r})")


def _rquh_address() -> str:
    """A syntactically valid regtest address for mining payouts."""
    from qeuph.crypto import address as addr_mod
    from qeuph.crypto import ml_dsa
    seed, pk, _sk = ml_dsa.generate_keypair()
    return addr_mod.hash_to_address(addr_mod.pk_to_hash(pk), "rquh")


# ---------------------------------------------------------------------------
# P0-b: the embedded node actually joins a P2P mesh
# ---------------------------------------------------------------------------
class TestEmbeddedP2P:
    """The web node must dial CLI nodes AND accept their inbound dials."""

    def test_web_node_dials_cli_node_and_syncs(self, tmp_path):
        d = CliDaemon(str(tmp_path), "alpha")
        d.wait_ready()
        import qeuph.web.server as ws
        saved = (ws.NODE, ws.REMOTE_RPC)
        try:
            nm = NodeManager("regtest",
                             data_root=str(tmp_path / "webroot"),
                             port_offset=free_port() % 500,
                             connect_peers=[f"127.0.0.1:{d.p2p}"],
                             p2p_host="127.0.0.1")
            # 1. the web node connected OUT to the CLI daemon...
            _wait_until(lambda: nm.node.peers, what="web node gained a peer")
            # ...and the CLI daemon sees the web node as an inbound peer
            _wait_until(
                lambda: rpc(d.url, "getconnectioncount") == 1,
                what="CLI node sees the web node's connection")

            # 2. blocks mined on the CLI node flow to the web node
            payout = _rquh_address()
            rpc(d.url, "generate", {"nblocks": 5, "address": payout})
            _wait_until(lambda: nm.chain.height() == 5,
                        what="web node synced to height 5")
            st = nm.status()
            assert st["peers"] == 1
            assert st["p2p_listening"] is True
            nm.close()
        finally:
            ws.NODE, ws.REMOTE_RPC = saved
            d.stop()

    def test_cli_node_dials_web_node_inbound(self, tmp_path):
        """Reverse direction: a CLI daemon dials the web node's P2P port."""
        import qeuph.web.server as ws
        saved = (ws.NODE, ws.REMOTE_RPC)
        d = None
        try:
            offset = free_port() % 500
            nm = NodeManager("regtest",
                             data_root=str(tmp_path / "webroot"),
                             port_offset=offset, p2p_host="127.0.0.1")
            d = CliDaemon(str(tmp_path), "beta",
                          connect=f"127.0.0.1:{nm.network.p2p_port}")
            d.wait_ready()
            _wait_until(lambda: nm.node.peers, what="web node accepted inbound")
            _wait_until(
                lambda: rpc(d.url, "getconnectioncount") == 1,
                what="CLI node connected to the web node")
            nm.close()
        finally:
            ws.NODE, ws.REMOTE_RPC = saved
            if d:
                d.stop()

    def test_port_clash_degrades_not_dies(self, tmp_path):
        """strict_listen=False: a busy P2P port degrades to outbound-only
        dialing instead of taking the node (and the UI with it) down."""
        from qeuph.core.chain import ChainManager
        from qeuph.core.mempool import Mempool
        from qeuph.node.node import QNode
        import asyncio

        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        net = REGTEST.with_(data_dir=str(tmp_path / "clash"), p2p_port=port)
        chain = ChainManager(net)
        mp = Mempool(chain.state_provider(), height_fn=chain.height,
                     mtp_fn=chain.median_time_past)
        node = QNode(net, chain, mp, bind_host="127.0.0.1",
                     strict_listen=False)
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(node.start())
            assert node.server is None
            assert node.listen_failed
            assert chain.height() >= 0          # the chain still works
            loop.run_until_complete(node.stop())
        finally:
            loop.close()
            chain.close()
            blocker.close()


# ---------------------------------------------------------------------------
# P0-a: the dashboard Send route
# ---------------------------------------------------------------------------
class TestUiSendRoute:
    @pytest.fixture(scope="class")
    def funded(self, tmp_path_factory):
        """A web node with a wallet and 105 matured regtest blocks."""
        root = str(tmp_path_factory.mktemp("qeuph-send"))
        nm = NodeManager("regtest", data_root=root)
        cli, srv, saved = _spin_web(nm)
        r = cli.post("/api/wallet", {"args": ["wallet", "create",
                                              "--unencrypted"]})
        assert r["ok"], r
        addrs = cli.get("/api/wallet/addresses?count=2")["addresses"]
        assert len(addrs) == 2
        cli.post("/api/miner/payout", {"address": addrs[0]["address"]})
        gen = cli.post("/api/generate", {"count": 105})
        assert gen["ok"], gen
        _wait_until(lambda: nm.chain.height() >= 105, what="105 blocks")
        yield cli, nm, addrs
        _teardown_web(srv, saved)
        nm.close()

    def test_send_broadcasts_into_mempool(self, funded):
        cli, nm, addrs = funded
        r = cli.post("/api/wallet/send", {
            "to": addrs[1]["address"], "amount": "1.5", "fee": "0.01",
            "from_index": 0, "passphrase": ""})   # unencrypted wallet
        assert r["success"], r
        # the tx is a real, relayable object: mempool holds it
        mp = cli.get("/api/mempool")
        assert mp["count"] >= 1
        assert r["txid"] in [t["txid"] for t in mp["transactions"]]
        # and the explorer view resolves it
        detail = cli.get(f"/api/tx/{r['txid']}")
        assert detail.get("mempool") is True

    def test_amount_is_decimal_exact(self, funded):
        """0.1 QUH must be exactly 10000000 quphi (no float drift)."""
        cli, nm, addrs = funded
        r = cli.post("/api/wallet/send", {
            "to": addrs[1]["address"], "amount": "0.1", "fee": "0.01",
            "from_index": 0, "passphrase": ""})
        assert r["success"], r
        detail = cli.get(f"/api/tx/{r['txid']}")
        values = [o["value"] for o in detail["outputs"]]
        assert 10_000_000 in values, values

    def test_encrypted_wallet_requires_passphrase(self, tmp_path_factory):
        root = str(tmp_path_factory.mktemp("qeuph-send-enc"))
        nm = NodeManager("regtest", data_root=root)
        cli, srv, saved = _spin_web(nm)
        try:
            r = cli.post("/api/wallet/generate", {"passphrase": "s3cret"})
            assert r["success"] and r["encrypted"]
            r2 = cli.post("/api/wallet/send", {
                "to": _rquh_address(),
                "amount": "1", "passphrase": ""})
            assert not r2["success"]
            assert "passphrase" in r2["error"]
        finally:
            _teardown_web(srv, saved)
            nm.close()

    def test_generate_without_passphrase_refused(self, funded):
        cli, nm, addrs = funded
        with pytest.raises(urllib.error.HTTPError) as e:
            cli.post("/api/wallet/generate", {})
        assert e.value.code == 400


# ---------------------------------------------------------------------------
# P0-c: remote-attach mode
# ---------------------------------------------------------------------------
class TestRemoteMode:
    @pytest.fixture(scope="class")
    def remote(self, tmp_path_factory):
        root = str(tmp_path_factory.mktemp("qeuph-remote"))
        d = CliDaemon(root, "remote-alpha")
        d.wait_ready()
        # the remote node gets a few blocks so the explorer has content
        rpc(d.url, "generate", {"nblocks": 3, "address": _rquh_address()})
        import qeuph.web.server as ws
        saved = (ws.NODE, ws.REMOTE_RPC)
        nm = NodeManager("regtest", data_root=str(tmp_path_factory.mktemp(
            "qeuph-remote-ui")), start_node=False)
        ws.NODE = nm
        ws.REMOTE_RPC = d.url
        port = free_port()
        srv = ThreadingHTTPServer(("127.0.0.1", port), QeuphHttpHandler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        yield WebClient(port), d
        srv.shutdown()
        srv.server_close()
        ws.NODE, ws.REMOTE_RPC = saved
        d.stop()

    def test_status_reports_remote(self, remote):
        cli, d = remote
        st = cli.get("/api/status")
        assert st["mode"] == "remote"
        assert st["remote_rpc"] == d.url
        assert st["height"] == 3

    def test_blocks_and_tx_views(self, remote):
        cli, d = remote
        blocks = cli.get("/api/blocks?limit=5")
        assert blocks["total_height"] == 3
        assert len(blocks["blocks"]) == 4      # 3 mined + genesis
        one = cli.get("/api/block/0")
        assert one["height"] == 0

    def test_rpc_bridge_forwards(self, remote):
        cli, d = remote
        res = cli.post("/api/rpc", {"method": "getblockcount"})
        assert res["ok"] is True
        assert res["result"] == 3

    def test_miner_routes_refused(self, remote):
        cli, d = remote
        with pytest.raises(urllib.error.HTTPError) as e:
            cli.post("/api/miner/start", {"payout": "x"})
        assert e.value.code == 403

    def test_chain_cli_bridge_refused(self, remote):
        cli, d = remote
        r = cli.post("/api/cli", {"args": ["chain", "info"]})
        assert r["ok"] is False
        assert "remote" in r["error"]

    def test_wallet_info_read_only(self, remote):
        cli, d = remote
        info = cli.get("/api/wallet/info")
        assert info["mode"] == "remote"
        assert info["exists"] is False
        # and polling did NOT create a wallet
        assert not os.path.exists(info["path"])


# ---------------------------------------------------------------------------
# P0-d: static dir hygiene
# ---------------------------------------------------------------------------
class TestStaticDirs:
    def test_repo_root_not_served(self):
        assert os.path.dirname(ROOT) not in [os.path.abspath(d)
                                             for d in STATIC_DIRS]
        assert ROOT not in [os.path.abspath(d) for d in STATIC_DIRS]

    def test_only_package_static_dir(self):
        assert STATIC_DIRS == [os.path.join(
            os.path.dirname(os.path.abspath(
                sys.modules["qeuph.web.server"].__file__)), "static")]


# ---------------------------------------------------------------------------
# P2-a: bind_host handling
# ---------------------------------------------------------------------------
class TestBindHost:
    def test_node_reports_listen_state(self, tmp_path):
        from qeuph.core.chain import ChainManager
        from qeuph.core.mempool import Mempool
        from qeuph.node.node import QNode
        import asyncio

        net = REGTEST.with_(data_dir=str(tmp_path / "bh"),
                            p2p_port=free_port())
        chain = ChainManager(net)
        mp = Mempool(chain.state_provider(), height_fn=chain.height,
                     mtp_fn=chain.median_time_past)
        node = QNode(net, chain, mp, bind_host="127.0.0.1")
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(node.start())
            assert node.server is not None
            assert node.listen_failed is None
            loop.run_until_complete(node.stop())
        finally:
            loop.close()
            chain.close()

    def test_strict_listen_raises_on_busy_port(self, tmp_path):
        from qeuph.core.chain import ChainManager
        from qeuph.core.mempool import Mempool
        from qeuph.node.node import QNode
        import asyncio

        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        net = REGTEST.with_(data_dir=str(tmp_path / "busy"),
                            p2p_port=port)
        chain = ChainManager(net)
        mp = Mempool(chain.state_provider(), height_fn=chain.height,
                     mtp_fn=chain.median_time_past)
        node = QNode(net, chain, mp, bind_host="127.0.0.1",
                     strict_listen=True)
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(OSError):
                loop.run_until_complete(node.start())
        finally:
            loop.close()
            chain.close()
            blocker.close()


# ---------------------------------------------------------------------------
# P2-b: exact JSON float handling in createrawtransaction
# ---------------------------------------------------------------------------
class TestCreateRawDecimal:
    def _rpc_service(self, tmp_path):
        from qeuph.core.chain import ChainManager
        from qeuph.core.mempool import Mempool
        from qeuph.network.rpc import RPCService
        from qeuph.node.node import QNode
        net = REGTEST.with_(data_dir=str(tmp_path / "cr"),
                            p2p_port=free_port(), rpc_port=free_port())
        chain = ChainManager(net)
        mp = Mempool(chain.state_provider(), height_fn=chain.height,
                     mtp_fn=chain.median_time_past)
        node = QNode(net, chain, mp)
        svc = RPCService(node, None, "127.0.0.1", free_port(), lambda: None)
        return svc, chain

    def test_point_one_is_exact(self, tmp_path):
        svc, chain = self._rpc_service(tmp_path)
        try:
            res = svc.dispatch("createrawtransaction", {
                "inputs": [{"txid": "ab" * 64, "index": 0, "nonce": 1}],
                "outputs": {_rquh_address(): 0.1}})
            from qeuph.core.tx import Transaction
            tx = Transaction.deserialize(bytes.fromhex(res["hex"]),
                                         allow_unsigned=True)
            assert tx.outputs[0].value == 10_000_000, tx.outputs[0].value
        finally:
            chain.close()

    def test_integer_quphi_passthrough(self, tmp_path):
        svc, chain = self._rpc_service(tmp_path)
        try:
            res = svc.dispatch("createrawtransaction", {
                "inputs": [{"txid": "ab" * 64, "index": 0, "nonce": 1}],
                "outputs": {_rquh_address(): 123456789}})
            from qeuph.core.tx import Transaction
            tx = Transaction.deserialize(bytes.fromhex(res["hex"]),
                                         allow_unsigned=True)
            assert tx.outputs[0].value == 123456789
        finally:
            chain.close()


# ---------------------------------------------------------------------------
# P1-b: no key material over HTTP
# ---------------------------------------------------------------------------
class TestNoPhraseOverHttp:
    def test_info_never_returns_phrase_even_unencrypted(
            self, tmp_path_factory):
        root = str(tmp_path_factory.mktemp("qeuph-phrase"))
        nm = NodeManager("regtest", data_root=root)
        cli, srv, saved = _spin_web(nm)
        try:
            cli.post("/api/wallet", {"args": ["wallet", "create",
                                              "--unencrypted"]})
            info = cli.get("/api/wallet/info")
            words = info["mnemonic"].split()
            # a BIP-39 phrase is 12/15/18/21/24 lowercase words; the answer
            # here is the "sealed" guidance sentence instead
            assert len(words) not in (12, 15, 18, 21, 24)
            assert "mnemonic" in info["mnemonic"] or "Sealed" in \
                info["mnemonic"]
            assert info["exists"] is True

            # GET never created anything when no wallet existed
        finally:
            _teardown_web(srv, saved)
            nm.close()

    def test_info_does_not_auto_create(self, tmp_path_factory):
        root = str(tmp_path_factory.mktemp("qeuph-noauto"))
        nm = NodeManager("regtest", data_root=root)
        cli, srv, saved = _spin_web(nm)
        try:
            path = nm.wallet_path()
            assert not os.path.exists(path)
            info = cli.get("/api/wallet/info")
            assert info["exists"] is False
            assert not os.path.exists(path), \
                "a GET must never create a wallet"
        finally:
            _teardown_web(srv, saved)
            nm.close()

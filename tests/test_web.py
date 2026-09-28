"""End-to-end checks of the web suite: HTTP surface, CLI mirror, safety."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from qeuph import constants as C
from qeuph.web.server import NodeManager, _subcommand_options, redact_secrets


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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


@pytest.fixture(scope="module")
def web(tmp_path_factory):
    from http.server import ThreadingHTTPServer
    from qeuph.web.server import QeuphHttpHandler
    import qeuph.web.server as ws
    # tmp_path_factory (not a hard-coded "/tmp/..." path) so each module run
    # gets a private data root.  A fixed path cannot be reused because the
    # embedded node keeps its SQLite store open, so on Windows the removal
    # below fails while a handle is live and the next run inherits state.
    root = str(tmp_path_factory.mktemp("qeuph-web"))
    ws.NODE = NodeManager("regtest", data_root=root, port_offset=0)
    ws.NODE.wallet_path()          # make sure the data directory exists
    port = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), QeuphHttpHandler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield WebClient(port), ws.NODE
    finally:
        srv.shutdown()
        srv.server_close()
        ws.NODE.close()
        ws.NODE = None


@pytest.fixture(scope="module", autouse=True)
def _created_wallet(web):
    """Every test that needs a spendable address shares one wallet."""
    cli, node = web
    r = cli.post("/api/wallet", {"args": ["wallet", "create",
                                          "--unencrypted"]})
    assert r["ok"], r
    return cli.get("/api/wallet/addresses?count=1")["addresses"][0]["address"]


class TestStaticAndStatus:
    def test_index_is_served(self, web):
        cli, _ = web
        status, body = cli.raw("/")
        assert status == 200
        assert "<title>Qeuph" in body
        assert "ML-DSA-87" in body

    def test_assets_served(self, web):
        cli, _ = web
        for path, needle in (("/style.css", "--cyan"),
                             ("/favicon.svg", "<svg")):
            status, body = cli.raw(path)
            assert status == 200, path
            assert needle in body, path

    def test_orphaned_app_js_is_gone(self, web):
        """app.js was an orphaned, untested second UI (zero element IDs in
        common with index.html).  It was deleted; the route must be gone so
        the dead asset can never be resurrected silently."""
        cli, _ = web
        with pytest.raises(urllib.error.HTTPError) as e:
            cli.raw("/app.js")
        assert e.value.code == 404

    def test_unknown_path_404(self, web):
        cli, _ = web
        with pytest.raises(urllib.error.HTTPError) as e:
            cli.get("/api/nope")
        assert e.value.code == 404

    def test_status_shape(self, web):
        cli, node = web
        s = cli.get("/api/status")
        assert s["network"] == "regtest"
        assert s["hrp"] == "rquh"
        assert s["node"] == "embedded"
        assert s["height"] >= 0
        assert s["mining_allowed"] is True
        assert s["rpc_url"].startswith("http://127.0.0.1:")
        assert s["genesis_hash"] == node.chain.genesis.hash.hex()
        assert s["version"] == C.VERSION
        assert "wallet" in s

    def test_mining_disabled_on_mainnet(self, tmp_path):
        nm = NodeManager("mainnet", data_root=str(tmp_path / "mn"))
        try:
            assert nm.status()["mining_allowed"] is False
            assert nm.status()["network"] == "mainnet"
            assert nm.status()["hrp"] == "quh"
        finally:
            nm.close()

    def test_network_profiles_do_not_leak(self, tmp_path):
        """Switching networks must not mutate the module-level profiles."""
        from qeuph.config import REGTEST, TESTNET
        before = (REGTEST.data_dir, REGTEST.p2p_port,
                  TESTNET.data_dir, TESTNET.p2p_port)
        nm = NodeManager("regtest", data_root=str(tmp_path / "leak"),
                         port_offset=10000)
        try:
            nm.open("testnet")
            assert nm.status()["network"] == "testnet"
            nm.open("regtest")
            assert nm.status()["network"] == "regtest"
        finally:
            nm.close()
        assert (REGTEST.data_dir, REGTEST.p2p_port,
                TESTNET.data_dir, TESTNET.p2p_port) == before


class TestViews:
    def test_blocks_view(self, web):
        cli, _ = web
        addr = cli.get("/api/wallet/addresses?count=1")["addresses"][0]["address"]
        cli.post("/api/generate", {"count": 2, "address": addr})
        r = cli.get("/api/blocks?limit=5")
        assert r["total_height"] >= 2
        assert r["blocks"]
        b = cli.get("/api/block/0")
        assert b["height"] == 0
        assert "26/Sep/2026" in b["transactions"][0]["inputs"][0]["data_text"]

    def test_unknown_block(self, web):
        cli, _ = web
        r = cli.get("/api/block/999999")
        assert r["ok"] is False and "not found" in r["error"]

    def test_mempool_view(self, web):
        cli, _ = web
        r = cli.get("/api/mempool")
        assert set(("count", "bytes", "maxbytes", "relayfee")) <= set(r)

    def test_emission_view(self, web):
        cli, _ = web
        r = cli.get("/api/emission")
        assert r["cap_quh"] == 31_500_000
        assert abs(r["exact_quh"] - 31_499_999.8593) < 1e-4
        assert r["epochs"] == 54
        assert r["final_reward_height"] == 11_130_000
        assert len(r["table"]) == 54

    def test_crypto_view(self, web):
        cli, _ = web
        r = cli.get("/api/crypto")
        assert r["signature_scheme"].startswith("ML-DSA-87")
        assert r["pk_size"] == 2592 and r["sig_size"] == 4627
        assert r["q"] == 8380417
        assert r["security_category"] == 5

    def test_crypto_live_test(self, web):
        cli, _ = web
        r = cli.post("/api/crypto/test", {"message": "hello"})
        assert r["verified"] and r["verified_pure_python"]
        assert r["tamper_detected"]
        assert r["pk_bytes"] == 2592 and r["sig_bytes"] == 4627

    def test_address_view(self, web):
        cli, _ = web
        r = cli.get("/api/address/nope")
        assert r["ok"] is False and "invalid" in r["error"]

    def test_peers_view(self, web):
        cli, _ = web
        assert cli.get("/api/peers")["peers"] == []


class TestRpcBridge:
    def test_single_call(self, web):
        cli, _ = web
        r = cli.post("/api/rpc", {"method": "getblockchaininfo", "params": {}})
        assert r["jsonrpc"] == "2.0"
        assert r["result"]["chain"] == "regtest"

    def test_batch(self, web):
        cli, _ = web
        r = cli.post("/api/rpc", {"batch": [
            {"method": "getblockcount", "id": 1},
            {"method": "getnetworkinfo", "id": 2},
            {"method": "nope", "id": 3}]})
        assert len(r["batch"]) == 3
        assert isinstance(r["batch"][0]["result"], int)
        assert r["batch"][1]["result"]["network"] == "regtest"
        assert r["batch"][2]["error"]["code"] == -32601

    def test_error_is_reported_not_raised(self, web):
        cli, _ = web
        r = cli.post("/api/rpc", {"method": "getbalance",
                                  "params": {"address": "nope"}})
        assert r["error"]["code"] == -32602


class TestCliMirror:
    def test_cli_tree(self, web):
        cli, _ = web
        tree = cli.get("/api/cli")
        assert "node" in tree["subcommands"]
        assert "wallet" in tree["subcommands"]
        assert "--rpc-user" in {o["name"] for o in
                                tree["subcommands"]["node"]["options"]}

    def test_run_readonly_cli(self, web):
        cli, _ = web
        r = cli.post("/api/cli", {"args": ["version"]})
        assert r["ok"] and "qeuph" in r["stdout"]
        r = cli.post("/api/cli", {"args": ["chain", "info", "--json"]})
        assert r["ok"] and json.loads(r["stdout"])["network"] == "regtest"

    def test_cli_data_dir_injection(self, web):
        """A `chain` command must read the embedded node's database."""
        cli, node = web
        addr = cli.get("/api/wallet/addresses?count=1")["addresses"][0]["address"]
        cli.post("/api/generate", {"count": 3, "address": addr})
        r = cli.post("/api/cli", {"args": ["chain", "info", "--json"]})
        assert json.loads(r["stdout"])["height"] == node.chain.height()
        assert str(node.network.data_dir) in r["args"]

    def test_blocked_commands(self, web):
        cli, _ = web
        r = cli.post("/api/cli", {"args": ["wallet", "create"]})
        assert r["ok"] is False
        assert "only" in r["error"]
        # a long-running daemon is never started from the browser
        r = cli.post("/api/cli", {"args": ["node"]})
        assert r["ok"] is False and "only" in r["error"]
        r = cli.post("/api/cli", {"args": ["web"]})
        assert r["ok"] is False

    def test_options_mirror(self):
        assert "--rpc" in _subcommand_options(["wallet", "send"])
        assert "--path" in _subcommand_options(["wallet", "create"])
        assert "--data-dir" in _subcommand_options(["chain", "info"])
        assert "--rpc" not in _subcommand_options(["chain", "info"])
        assert "--threads" in _subcommand_options(["node"])

    def test_secret_redaction(self):
        phrase = " ".join(["abandon"] * 23 + ["art"])
        out = redact_secrets(f"phrase: {phrase}\n")
        assert phrase not in out
        assert "redacted" in out


class TestWalletOverHttp:
    def test_create_and_derive(self, web, tmp_path):
        """Creating a wallet in a throwaway data dir and reading it back."""
        cli, _ = web
        r = cli.post("/api/wallet", {"args": ["wallet", "create",
                                              "--unencrypted",
                                              "--path",
                                              str(tmp_path / "n.json")]})
        assert r["ok"], r
        assert "rquh1" in r["stdout"]
        assert "redacted" in r["stdout"], "the phrase must never be returned"

    def test_addresses_view(self, web):
        cli, _ = web
        r = cli.get("/api/wallet/addresses?count=3")
        assert r["exists"]
        assert len(r["addresses"]) == 3
        for row in r["addresses"]:
            assert row["address"].startswith("rquh1")
            assert "seed" not in json.dumps(row).lower()
            assert "mnemonic" not in json.dumps(row).lower()

    def test_mnemonic_refused(self, web):
        cli, _ = web
        for argv in (["wallet", "mnemonic"],
                     ["wallet", "backup", "--out-mnemonic"],
                     ["wallet", "show", "--show-seed"]):
            r = cli.post("/api/wallet", {"args": argv})
            assert r["ok"] is False, argv
            assert "qeuph wallet mnemonic" in r["error"]

    def test_send_flow(self, web):
        cli, node = web
        addrs = cli.get("/api/wallet/addresses?count=1")["addresses"]
        addr = addrs[0]["address"]
        # make it spendable
        cli.post("/api/generate", {"count": 101, "address": addr})
        bal = cli.post("/api/rpc", {"method": "getbalance",
                                    "params": {"address": addr}})["result"]
        assert bal["balance_quh"] > 0
        r = cli.post("/api/wallet", {
            "args": ["wallet", "send", "--to", addr, "--amount", "1",
                     "--fee", "0.01"],
            "passphrase": ""})
        assert r["ok"], r
        assert "txid" in r["stdout"]
        assert cli.get("/api/mempool")["count"] >= 1
        cli.post("/api/generate", {"count": 1, "address": addr})
        assert cli.get("/api/mempool")["count"] == 0

    def test_sweep_dry_run(self, web):
        cli, _ = web
        addrs = cli.get("/api/wallet/addresses?count=2")["addresses"]
        r = cli.post("/api/wallet", {
            "args": ["wallet", "sweep", "--to", addrs[1]["address"]],
            "passphrase": ""})
        assert r["ok"], r
        assert "dry run" in r["stdout"]


class TestMinerControls:
    def test_generate_requires_a_target(self, web):
        cli, node = web
        with pytest.raises(urllib.error.HTTPError):
            cli.post("/api/generate", {"count": 1})

    def test_miner_lifecycle(self, web):
        cli, _ = web
        addrs = cli.get("/api/wallet/addresses?count=1")["addresses"]
        r = cli.post("/api/miner/start", {"payout": addrs[0]["address"],
                                          "threads": 2})
        assert r["ok"] and r["mining"]
        time.sleep(1.5)
        s = cli.get("/api/status")
        assert s["mining"] is True
        assert s["threads"] == 2
        cli.post("/api/miner/stop", {})
        assert cli.get("/api/status")["mining"] is False

    def test_bad_payout_rejected(self, web):
        cli, _ = web
        with pytest.raises(urllib.error.HTTPError):
            cli.post("/api/miner/payout", {"address": "nope"})

    def test_threads_clamped(self, web):
        cli, _ = web
        r = cli.post("/api/miner/threads", {"threads": 99})
        assert r["threads"] == 16
        cli.post("/api/miner/threads", {"threads": 1})


class TestSafety:
    def test_remote_bind_refused(self):
        from qeuph.web.server import serve
        with pytest.raises(SystemExit, match="refusing to bind"):
            serve(host="0.0.0.0", port=free_port(), embedded="off")

    def test_node_never_exposes_key_material(self, web):
        cli, _ = web
        for path in ("/api/status", "/api/wallet/addresses"):
            body = json.dumps(cli.get(path))
            assert "master_seed" not in body
            assert "mnemonic" not in body
            assert "ciphertext" not in body

    def test_generate_capped(self, web):
        cli, _ = web
        addr = cli.get("/api/wallet/addresses?count=1")["addresses"][0]["address"]
        r = cli.post("/api/generate", {"count": 100000, "address": addr})
        assert r["ok"] and r["count"] <= 200

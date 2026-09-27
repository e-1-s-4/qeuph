"""Regression tests for the HTTP-surface defects found in the 2026 pass.

These pin the contract documented in README.md "Key safety properties of the
UI" and docs/PROTOCOL.md "Web suite": no key material over HTTP, no solo
mining on mainnet, no passphrase echo, and exactly one HTTP response per
request on a keep-alive connection.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from qeuph import constants as C
from qeuph.config import REGTEST
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.network.rpc import READ_ONLY_METHODS, RPCService
from qeuph.web.server import (ALLOWED_CHAIN_SUBCOMMANDS, ALLOWED_CLI_CMDS,
                              ALLOWED_WALLET_SUBCOMMANDS, NodeManager,
                              QeuphHttpHandler, _same_origin)
from qeuph.wallet import keystore
from qeuph.wallet.wallet import Wallet

from .conftest import free_port


def _rpc_service(net, user=None, password=None):
    chain = ChainManager(net)
    mempool = Mempool(chain.state_provider(), height_fn=chain.height,
                      mtp_fn=chain.median_time_past)
    from qeuph.node.node import QNode
    node = QNode(net, chain, mempool)
    port = free_port()
    svc = RPCService(node, None, "127.0.0.1", port, lambda: None,
                     rpc_user=user, rpc_password=password)
    return svc, chain, node


class TestMainnetMiningIsRefused:
    """The UI must not be able to reorganise or spend real value by accident."""

    def test_rpc_startminer_refused_on_mainnet(self, tmp_path):
        net = REGTEST.with_(name="mainnet", hrp="quh",
                            data_dir=str(tmp_path / "mn"),
                            p2p_port=free_port(), rpc_port=free_port())
        svc, chain, node = _rpc_service(net)
        try:
            with pytest.raises(Exception) as ei:
                svc.dispatch("startminer", {"address": None})
            assert "mainnet" in str(ei.value).lower()
        finally:
            chain.close()

    def test_read_only_get_allowlist_excludes_mutations(self):
        for m in ("startminer", "generate", "stop", "stopminer", "submitblock",
                  "sendrawtransaction", "rescan"):
            assert m not in READ_ONLY_METHODS
        for m in ("getblockchaininfo", "getblockcount", "getbalance",
                  "getbestblockhash"):
            assert m in READ_ONLY_METHODS

    def test_mutating_rpc_refused_over_get(self, tmp_path):
        net = REGTEST.with_(data_dir=str(tmp_path / "ro"),
                            p2p_port=free_port(), rpc_port=free_port())
        svc, chain, node = _rpc_service(net)
        import asyncio

        loop = asyncio.new_event_loop()
        t = threading.Thread(target=loop.run_forever, daemon=True)
        t.start()
        svc._loop = loop
        try:
            svc.start_background(loop)
            time.sleep(0.3)
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{svc.port}/?method=startminer", timeout=10
            ) as r:
                doc = json.loads(r.read())
            assert "error" in doc
            assert "GET" in doc["error"]["message"]
        finally:
            svc.stop()
            loop.call_soon_threadsafe(loop.stop)
            chain.close()

    def test_destructive_commands_not_reachable(self):
        """`chain truncate` / `reindex` rewrite the embedded node's DB, and
        `rpc --url` is an arbitrary outbound URL (SSRF)."""
        assert "rpc" not in ALLOWED_CLI_CMDS
        assert "mine" not in ALLOWED_CLI_CMDS
        assert "truncate" not in ALLOWED_CHAIN_SUBCOMMANDS
        assert "reindex" not in ALLOWED_CHAIN_SUBCOMMANDS
        for verb in ("sign", "passwd", "backup", "restore", "mnemonic"):
            assert verb not in ALLOWED_WALLET_SUBCOMMANDS


class TestRpcAuthRobustness:
    def test_non_ascii_authorization_gets_401_not_a_dropped_connection(
            self, tmp_path):
        """compare_digest raises TypeError on non-ASCII str operands; the
        exception escaped the handler, so the client got a reset instead of
        a challenge."""
        net = REGTEST.with_(data_dir=str(tmp_path / "auth"),
                            p2p_port=free_port(), rpc_port=free_port())
        svc, chain, node = _rpc_service(net, user="node", password="pw")
        import asyncio

        loop = asyncio.new_event_loop()
        threading.Thread(target=loop.run_forever, daemon=True).start()
        svc._loop = loop
        try:
            svc.start_background(loop)
            time.sleep(0.3)
            body = json.dumps({"jsonrpc": "2.0", "id": 1,
                               "method": "getblockcount"}).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{svc.port}/", data=body,
                headers={"Content-Type": "application/json",
                         "Authorization": "Basic " + "éé"})
            with pytest.raises(urllib.error.HTTPError) as ei:
                urllib.request.urlopen(req, timeout=10)
            assert ei.value.code == 401
        finally:
            svc.stop()
            loop.call_soon_threadsafe(loop.stop)
            chain.close()

    def test_oversized_body_answers_413_and_closes(self, tmp_path):
        net = REGTEST.with_(data_dir=str(tmp_path / "big"),
                            p2p_port=free_port(), rpc_port=free_port())
        svc, chain, node = _rpc_service(net)
        import asyncio

        loop = asyncio.new_event_loop()
        threading.Thread(target=loop.run_forever, daemon=True).start()
        svc._loop = loop
        try:
            svc.start_background(loop)
            time.sleep(0.3)
            s = socket.create_connection(("127.0.0.1", svc.port), timeout=10)
            payload = b"x" * (2 * 1024 * 1024)
            s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\n"
                      b"Content-Type: application/json\r\n"
                      b"Content-Length: " + str(len(payload)).encode()
                      + b"\r\n\r\n" + payload)
            s.settimeout(15)
            chunks = b""
            try:
                while len(chunks) < 4096:
                    d = s.recv(4096)
                    if not d:
                        break
                    chunks += d
            except socket.timeout:
                pass
            s.close()
            assert b"413" in chunks.split(b"\r\n")[0], chunks[:120]
        finally:
            svc.stop()
            loop.call_soon_threadsafe(loop.stop)
            chain.close()


class TestSameOriginCors:
    def test_same_origin_matching(self):
        assert _same_origin("http://127.0.0.1:3000", "127.0.0.1:3000")
        assert not _same_origin("http://evil.example", "127.0.0.1:3000")
        assert not _same_origin("", "127.0.0.1:3000")
        assert not _same_origin("javascript:alert(1)", "127.0.0.1:3000")


class TestWebSurface:
    @pytest.fixture()
    def web(self, tmp_path):
        import qeuph.web.server as ws
        ws.NODE = NodeManager("regtest", data_root=str(tmp_path / "w"),
                              port_offset=0)
        ws.NODE.wallet_path()
        srv = ThreadingHTTPServer(("127.0.0.1", free_port()),
                                  QeuphHttpHandler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            yield f"http://127.0.0.1:{srv.server_address[1]}"
        finally:
            srv.shutdown()
            srv.server_close()
            ws.NODE.close()
            ws.NODE = None

    def _post(self, base, path, payload):
        req = urllib.request.Request(
            base + path, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())

    def test_passphrase_never_in_response_body(self, web):
        Wallet.create(hrp="rquh", network="regtest").save(
            f"{web.split('//')[1]}", "pw") if False else None
        st, doc = self._post(web, "/api/wallet", {
            "args": ["wallet", "show"],
            "passphrase": "hunter2SUPERSECRET"})
        assert "hunter2SUPERSECRET" not in json.dumps(doc)

    def test_recovery_phrase_never_in_response_body(self, web):
        phrase = " ".join(["abandon"] * 23 + ["art"])
        st, doc = self._post(web, "/api/wallet", {
            "args": ["wallet", "restore", "--from-mnemonic", phrase]})
        assert phrase not in json.dumps(doc)

    def test_address_count_is_clamped(self, web):
        """An unbounded `count` ran a PBKDF2 unlock plus a keygen per index
        while holding the node lock, permanently wedging the server."""
        with urllib.request.urlopen(
                web + "/api/wallet/addresses?count=2000000", timeout=30) as r:
            doc = json.loads(r.read())
        assert len(doc["addresses"]) <= 50

    def test_bad_query_parameter_is_400_not_500(self, web):
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(web + "/api/blocks?limit=abc", timeout=10)
        assert ei.value.code == 400

    def test_no_wildcard_cors_header(self, web):
        req = urllib.request.Request(web + "/api/status",
                                     headers={"Origin": "http://evil.example"})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.headers.get("Access-Control-Allow-Origin") is None

    def test_miner_payout_refused_on_mainnet(self, web, tmp_path):
        import qeuph.web.server as ws
        was = ws.NODE
        try:
            ws.NODE = NodeManager("mainnet", data_root=str(tmp_path / "mn"),
                                  port_offset=0)
            with pytest.raises(urllib.error.HTTPError) as ei:
                self._post(web, "/api/miner/payout", {"address": "quh1" + "q" * 100})
            assert ei.value.code == 403
        finally:
            ws.NODE.close()
            ws.NODE = was

    def test_one_response_per_request_on_keepalive(self, web):
        """A helper that returned `send_error_json(...)` inside a
        `send_json(...)` wrapper wrote TWO complete HTTP responses to one
        keep-alive connection."""
        s = socket.create_connection(tuple(web.split("//")[1].split(":")),
                                     timeout=20)
        s.settimeout(20)
        body = json.dumps({"payout": "not-a-real-address"}).encode()
        s.sendall(b"POST /api/miner/start HTTP/1.1\r\nHost: x\r\n"
                  b"Content-Type: application/json\r\nContent-Length: "
                  + str(len(body)).encode() + b"\r\n\r\n" + body)
        data = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                data += d
                if b"\r\n\r\n" in data and data.count(b"HTTP/1.1") >= 1:
                    # give the server a moment to (incorrectly) write more
                    s.settimeout(2)
        except socket.timeout:
            pass
        s.close()
        assert data.count(b"HTTP/1.1") == 1, data[:400]


import time  # noqa: E402  (used by the async fixture bodies above)

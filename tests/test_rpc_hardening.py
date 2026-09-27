"""Tests for the availability and transport hardening of the RPC surface.

Covers the per-connection rate limit, the loopback bind policy, the exact
decimal amount conversion, and the same-origin CORS posture.
"""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from qeuph import constants as C
from qeuph.config import REGTEST
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.network import rpc as rpc_mod
from qeuph.node.node import QNode

from .conftest import free_port


@pytest.fixture()
def rpc_server(tmp_path):
    import asyncio
    net = REGTEST.with_(data_dir=str(tmp_path / "n"),
                        p2p_port=free_port(), rpc_port=free_port())
    chain = ChainManager(net)
    mempool = Mempool(chain.state_provider(), height_fn=chain.height,
                      mtp_fn=chain.median_time_past)
    node = QNode(net, chain, mempool)
    port = free_port()
    svc = rpc_mod.RPCService(node, None, "127.0.0.1", port, lambda: None)
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    svc._loop = loop
    svc.start_background(loop)
    time.sleep(0.3)
    try:
        yield f"http://127.0.0.1:{port}", svc, chain
    finally:
        svc.stop()
        loop.call_soon_threadsafe(loop.stop)
        # the loop runs on its own thread, so give it a moment to notice the
        # stop before closing (closing a running loop raises)
        t = threading.Thread(target=loop.close, daemon=True)
        t.start()
        t.join(timeout=2)
        chain.close()


def _post(base, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(base + "/", data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def _burst_on_one_connection(base, count):
    """Issue `count` calls down a SINGLE keep-alive connection.

    The limiter is per connection, so a test that opened a fresh socket per
    request would measure nothing.
    """
    import http.client
    host = base.split("//", 1)[1].split(":")[0]
    port = int(base.rsplit(":", 1)[1])
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "method": "getblockcount"}).encode()
    headers = {"Content-Type": "application/json",
               "Content-Length": str(len(body))}
    codes = []
    conn = http.client.HTTPConnection(host, port, timeout=20)
    try:
        for _ in range(count):
            try:
                conn.request("POST", "/", body=body, headers=headers)
                resp = conn.getresponse()
                resp.read()
                codes.append(resp.status)
                if resp.will_close:
                    break
            except Exception:
                break
    finally:
        conn.close()
    return codes


class TestRateLimit:
    def test_burst_then_429(self, rpc_server):
        """The limiter the module docstring promised was declared but never
        wired up, so one client could pin a worker thread indefinitely."""
        base, svc, _chain = rpc_server
        codes = _burst_on_one_connection(
            base, rpc_mod.RATE_LIMIT_CALLS + 60)
        assert 429 in codes, f"a sustained burst must be limited, got {codes[-5:]}"
        assert codes.count(200) >= rpc_mod.RATE_LIMIT_CALLS

    def test_limit_is_per_connection(self, rpc_server):
        """Being limited on one socket must not lock out a fresh one."""
        base, svc, _chain = rpc_server
        _burst_on_one_connection(base, rpc_mod.RATE_LIMIT_CALLS + 60)
        # a new connection gets a fresh budget
        assert _post(base, "getblockcount").get("result") == 0

    def test_budget_recovers_after_the_window(self, rpc_server, monkeypatch):
        monkeypatch.setattr(rpc_mod, "RATE_LIMIT_WINDOW", 0.3)
        base, svc, _chain = rpc_server
        _burst_on_one_connection(base, rpc_mod.RATE_LIMIT_CALLS + 60)
        time.sleep(0.6)
        codes = _burst_on_one_connection(base, 5)
        assert codes and all(c == 200 for c in codes)


class TestCors:
    def test_no_wildcard_origin(self, rpc_server):
        base, _svc, _chain = rpc_server
        req = urllib.request.Request(base + "/?method=getblockcount",
                                     headers={"Origin": "http://evil.example"})
        with urllib.request.urlopen(req, timeout=20) as r:
            assert r.headers.get("Access-Control-Allow-Origin") is None

    def test_same_origin_is_echoed(self, rpc_server):
        base, _svc, _chain = rpc_server
        origin = base.replace("http://", "http://")
        req = urllib.request.Request(base + "/?method=getblockcount",
                                     headers={"Origin": origin})
        with urllib.request.urlopen(req, timeout=20) as r:
            assert r.headers.get("Access-Control-Allow-Origin") == origin


class TestLoopbackPolicy:
    def test_is_loopback(self):
        from qeuph.web.server import _is_loopback
        assert _is_loopback("127.0.0.1")
        assert _is_loopback("127.0.0.2")
        assert _is_loopback("::1")
        assert _is_loopback("localhost")
        # "" binds every interface and must never be treated as loopback
        assert not _is_loopback("")
        assert not _is_loopback("0.0.0.0")
        assert not _is_loopback("192.168.1.10")
        assert not _is_loopback("example.org")

    def test_refuses_non_loopback_without_flag(self, tmp_path):
        from qeuph.web.server import serve
        with pytest.raises(SystemExit, match="refusing to bind"):
            serve(host="0.0.0.0", port=free_port(),
                  data_root=str(tmp_path / "x"))


class TestAmountConversion:
    def test_exact_decimal_conversion(self):
        """`round(x * 10**8)` on a binary float is lossy and uses banker's
        rounding, so typed amounts did not always mean what was written."""
        from qeuph.cli.main import _to_quphi
        assert _to_quphi(1, "amount") == 100_000_000
        assert _to_quphi(0.1, "amount") == 10_000_000
        assert _to_quphi("0.07", "amount") == 7_000_000
        assert _to_quphi(0.00000001, "amount") == 1
        assert _to_quphi(1.5, "fee") == 150_000_000
        # the float path lost or invented quphi here
        assert _to_quphi(0.29, "amount") == 29_000_000

    def test_rejects_sub_quphi_precision(self):
        from qeuph.cli.main import _to_quphi
        with pytest.raises(SystemExit, match="decimal places"):
            _to_quphi("0.000000005", "amount")

    def test_rejects_negative_and_overflow(self):
        from qeuph.cli.main import _to_quphi
        with pytest.raises(SystemExit, match="negative"):
            _to_quphi(-1, "amount")
        with pytest.raises(SystemExit, match="64-bit"):
            _to_quphi(1e30, "amount")

    def test_rejects_garbage(self):
        from qeuph.cli.main import _to_quphi
        with pytest.raises(SystemExit, match="not a number"):
            _to_quphi("abc", "amount")


class TestStaticAssets:
    def test_cwd_is_not_a_static_source(self):
        """Serving <cwd>/index.html from the trusted loopback origin let any
        file that happened to land in the cwd be served as the site root."""
        import os
        from qeuph.web import server as ws
        assert os.getcwd() not in [os.path.abspath(d) for d in ws.STATIC_DIRS]

    def test_allowlist_is_still_enforced(self, tmp_path, monkeypatch):
        from qeuph.web import server as ws
        evil = tmp_path / "evil"
        evil.mkdir()
        (evil / "index.html").write_text("pwned")
        monkeypatch.setattr(ws, "STATIC_DIRS", [str(evil)])
        assert "index.html" in ws.STATIC_FILES
        # a traversal attempt never matches the allowlist
        assert "index.html" not in ("../../etc/passwd", "..", "evil/../../x")

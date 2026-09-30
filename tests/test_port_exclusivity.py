"""Listener hardening: a local process must not be able to take over the
RPC, web or P2P port, and "port in use" must be detected on every platform.

The defect this pins: `http.server.HTTPServer` inherits
`allow_reuse_address = 1`, and on Windows SO_REUSEADDR means "let any other
process bind this address too" rather than POSIX's "reuse a TIME_WAIT
address".  A second, unprivileged local process could therefore bind the RPC
port and impersonate the node - answering the operator's `stop`,
`startminer` and `sendrawtransaction` calls while the real node quietly stops
serving.  `asyncio`'s `reuse_address=True` (the P2P listener) had the same
problem.  A second defect: the port-busy check compared `errno == 98`, which
is EADDRINUSE on Linux and never true on Windows, so the fallback path was
dead code on the platform that needed it.
"""
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from qeuph.network.listen import (ExclusiveHTTPServer, listener_socket,
                                  make_http_server, port_busy)


def _hijack_attempt(host: str, port: int) -> bool:
    """What another local process does: bind the port with SO_REUSEADDR."""
    s = socket.socket()
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(5)
        return True
    except OSError:
        return False
    finally:
        s.close()


class Quiet(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


class TestNoPortHijacking:
    def test_http_listener_cannot_be_hijacked(self):
        srv = make_http_server("127.0.0.1", 0, Quiet, name="test")
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            assert not _hijack_attempt("127.0.0.1", port), (
                "a second process could bind the RPC/web port")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_p2p_listener_socket_cannot_be_hijacked(self):
        sock = listener_socket("127.0.0.1", 0)
        port = sock.getsockname()[1]
        sock.listen(8)
        try:
            assert not _hijack_attempt("127.0.0.1", port), (
                "a second process could bind the P2P port")
        finally:
            sock.close()

    def test_a_node_actually_uses_the_exclusive_socket(self):
        """The P2P listener of a real QNode goes through the same path."""
        import asyncio
        import dataclasses
        from qeuph.config import REGTEST
        from qeuph.core.chain import ChainManager
        from qeuph.core.mempool import Mempool
        from qeuph.node.node import QNode

        def _free_port():
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        async def scenario(tmp_path):
            net = dataclasses.replace(REGTEST, data_dir=os.path.join(tmp_path, "c"),
                                      p2p_port=_free_port(),
                                      rpc_port=_free_port())
            chain = ChainManager(net)
            node = QNode(net, chain,
                         Mempool(chain.state_provider(), height_fn=chain.height),
                         bind_host="127.0.0.1")
            await node.start()
            try:
                port = node.network.p2p_port
                assert not _hijack_attempt("127.0.0.1", port)
            finally:
                await node.stop()
                chain.close()

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            asyncio.run(scenario(tmp))

    @pytest.mark.skipif(os.name != "nt", reason="Windows SO_REUSEADDR semantics")
    def test_the_stdlib_server_really_was_hijackable(self):
        """Characterisation: this is what the fix is protecting against."""
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            assert _hijack_attempt("127.0.0.1", port)
        finally:
            srv.shutdown()
            srv.server_close()
        assert ExclusiveHTTPServer.allow_reuse_address is False


class TestPortBusyDetection:
    def test_every_platform_errno_is_recognised(self):
        for code in (98, 10048, 10049, 10013):     # POSIX + Windows
            assert port_busy(OSError(code, "in use")), code
        assert not port_busy(OSError(1, "Operation not permitted"))
        assert not port_busy(ValueError("nope"))

    def test_rpc_falls_back_when_its_port_is_taken(self):
        """A busy --rpc-port must not crash the daemon on any platform."""
        from qeuph.network.rpc import RPCService
        import asyncio
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy = blocker.getsockname()[1]
        svc = RPCService(node=None, miner=None, host="127.0.0.1", port=busy,
                        get_stop_event=lambda: asyncio.Event())
        loop = asyncio.new_event_loop()
        try:
            svc.start_background(loop)
            try:
                assert svc.port != busy
                assert svc.port > 0
                assert svc._server is not None
            finally:
                svc.stop()
        finally:
            blocker.close()
            loop.close()

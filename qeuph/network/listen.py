"""
Listener sockets for the Qeuph node.

Two concerns live here because both of Qeuph's listeners share them:

*Windows port hijacking.*  On Windows SO_REUSEADDR does not mean "reuse a
TIME_WAIT address" as it does on POSIX - it means "let any other process bind
this address as well".  `http.server.HTTPServer` (and `asyncio`'s
`reuse_address=True`) therefore produce listeners that an unprivileged local
process can steal: a second process binding 127.0.0.1:19091 first would
answer the operator's `stop`, `startminer` and `sendrawtransaction` calls, and
the real node would have silently lost its control port.  Windows gets
SO_EXCLUSIVEADDRUSE here; every other platform keeps the stdlib behaviour,
which is correct on POSIX.  There is deliberately NO shared-address fallback:
if the port really belongs to another process, the caller must say so (or
pick a different port) rather than end up sharing it with it.

*Platform-correct "port in use" detection.*  EADDRINUSE is 98 on POSIX and
10048/10049 (WSAEADDRINUSE/WSAENOPORT) on Windows, and a reserved or
hijacked port surfaces as 10013 (WSAEACCES).  Matching 98 alone made the
port-busy fallbacks dead code on the platform where they matter.
"""
from __future__ import annotations

import errno
import logging
import os
import socket
from http.server import ThreadingHTTPServer

logger = logging.getLogger("qeuph.listen")

PORT_BUSY_ERRNOS = frozenset({
    # EADDRINUSE: 98 on Linux/macOS, 100 through the Windows `errno` module,
    # 10048 (WSAEADDRINUSE) from a raw socket.  10049/10013 are the other two
    # Windows shapes of the same condition (WSAENOPORT, WSAEACCES for a port
    # that is reserved or held exclusively).
    98, errno.EADDRINUSE, 100, 10048, 10049, 10013,
    getattr(errno, "WSAEADDRINUSE", 10048),
    getattr(errno, "WSAENOPORT", 10049),
    getattr(errno, "WSAEACCES", 10013),
})


def port_busy(exc: OSError) -> bool:
    """True when `exc` means "somebody already owns that port"."""
    return getattr(exc, "errno", None) in PORT_BUSY_ERRNOS


class ExclusiveHTTPServer(ThreadingHTTPServer):
    """HTTP listener that cannot be taken over by another process."""

    daemon_threads = True
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET,
                                   socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def make_http_server(host: str, port: int, handler,
                     *, name: str = "http") -> ThreadingHTTPServer:
    """Bind (host, port) for an HTTP server, exclusively on Windows."""
    try:
        return ExclusiveHTTPServer((host, port), handler)
    except OSError as e:
        if os.name == "nt" and port_busy(e):
            logger.warning("%s: %s:%d is already in use, and Qeuph binds "
                           "exclusively on Windows so no other process can "
                           "share it", name, host, port)
        raise


def listener_socket(host: str, port: int) -> socket.socket:
    """A bound, not-yet-listening P2P socket (Windows-exclusive)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host or "0.0.0.0", int(port)))
    return sock


__all__ = ["PORT_BUSY_ERRNOS", "port_busy", "ExclusiveHTTPServer",
           "make_http_server", "listener_socket"]

"""
Peer-to-peer node service (asyncio TCP).

Responsibilities:
  * handshake (version/verack) with strict network/protocol checks, a peer
    score/ban table and per-peer rate limiting
  * headers-first initial block download with a continuous sync driver and
    bounded in-flight block requests
  * block/transaction relay with inv/getdata (non-blocking per-peer queues)
  * peer discovery (getaddr/addr), keepalive pings, idle pruning, periodic
    reconnect toward TARGET_OUTBOUND_PEERS
  * feeding validated blocks and transactions into the ChainManager/Mempool

This is the Qeuph port of QRL's twisted-based node (qrl/core/node.py +
qrl/socket/*): same state machine (unsynced -> syncing -> synced), but on
stdlib asyncio.

Shutdown contract: stop() closes peer writers BEFORE waiting on the server
so connection handlers exit promptly (Python 3.12+ wait_closed() semantics
wait for all handlers); read loops race against the stop event.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Set, Tuple

from qeuph import constants as C
from qeuph.config import Network
from qeuph.core import pow as pow_mod
from qeuph.core.block import Block, BlockHeader
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.tx import Transaction
from qeuph.core.validation import BlockValidationError, TxValidationError
from qeuph.network.protocol import FrameReader, encode_frame
from qeuph.network.listen import listener_socket

logger = logging.getLogger("qeuph.node")

# coalesce height re-announcements during a fast sync, then flush the tail
ANNOUNCE_MIN_INTERVAL = 0.5
ANNOUNCE_FLUSH_INTERVAL = 0.5

# backoff for the peers named by --connect
PEER_RETRY_MIN_INTERVAL = 1.0
PEER_RETRY_MAX_INTERVAL = 10.0


class PeerMisbehaved(Exception):
    """Raised by a handler to disconnect and (optionally) ban the peer."""


class Peer:
    """One connected remote, with its own bounded send queue."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 node: "QNode", inbound: bool):
        self.reader = reader
        self.writer = writer
        self.node = node
        self.inbound = inbound
        self.reader_buf = FrameReader(node.network.magic)
        self.peer_version: Optional[dict] = None
        self.veracked = False
        self.best_height = -1
        self.last_seen = time.time()
        self.last_ping_sent = 0.0
        self.connected_at = time.time()
        self.start_height = node.chain.height()
        # token-bucket rate limit
        self._tokens = float(C.PEER_MSG_BURST)
        self._last_token = time.time()
        # outbound send queue + writer task
        self.send_q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self.writer_task: Optional[asyncio.Task] = None
        self.closing = False
        # misbehaviour score (ban-scoring, decayed over time)
        self.score = 0
        self.score_at = time.time()
        self.banned_reason = ""
        # blocks we have asked this peer for and not yet received
        self.requested: Set[bytes] = set()
        self.synced_blocks: int = 0
        # our height as last advertised to THIS peer, so a re-announcement is
        # only sent when it actually changed
        self.announced_height: int = -1
        self.last_announce: float = 0.0
        # a coalesced announcement we still owe this peer
        self.announce_pending: bool = False

    # ------------------------------------------------------------------
    @property
    def ip(self) -> str:
        """Remote IP (empty when the transport does not report a peer)."""
        hp = self.host_port
        return hp[0] if hp else ""

    @property
    def addr(self) -> str:
        peer = self.writer.get_extra_info("peername")
        return f"{peer[0]}:{peer[1]}" if peer else "?"

    @property
    def host_port(self) -> Optional[Tuple[str, int]]:
        peer = self.writer.get_extra_info("peername")
        return (peer[0], peer[1]) if peer else None

    # ------------------------------------------------------------------
    def allow_message(self) -> bool:
        """Token bucket: True when the message passes rate limiting."""
        now = time.time()
        dt = now - self._last_token
        self._last_token = now
        self._tokens = min(float(C.PEER_MSG_BURST),
                           self._tokens + dt * C.PEER_MSG_BUDGET)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def penalise(self, points: int, reason: str = ""):
        """Add misbehaviour points; returns True when the peer is now banned."""
        self.score += int(points)
        self.banned_reason = reason or self.banned_reason
        if self.score >= C.BAN_SCORE_THRESHOLD:
            self.node.ban(self, self.banned_reason or "score threshold")
            return True
        return False

    def decayed_score(self) -> int:
        elapsed = time.time() - self.score_at
        return max(0, int(self.score - elapsed * C.BAN_SCORE_DECAY))

    # ------------------------------------------------------------------
    async def send(self, command: str, payload: dict):
        """Queue a frame; the peer's writer task drains it.  Raises
        asyncio.QueueFull for persistently slow peers."""
        if self.closing:
            return
        self.send_q.put_nowait(encode_frame(command, payload,
                                             self.node.network.magic))

    def try_send(self, command: str, payload: dict) -> bool:
        if self.closing:
            return False
        try:
            self.send_q.put_nowait(
                encode_frame(command, payload, self.node.network.magic))
            return True
        except asyncio.QueueFull:
            return False

    async def _writer_loop(self):
        try:
            while not self.closing:
                frame = await self.send_q.get()
                if frame is None:          # shutdown sentinel
                    break
                self.writer.write(frame)
                await self.writer.drain()
        except (ConnectionError, asyncio.CancelledError, RuntimeError, OSError):
            pass
        finally:
            try:
                self.writer.close()
            except Exception:
                pass

    def kick(self):
        """Stop the peer's writer and close the connection."""
        if self.closing:
            return
        self.closing = True
        try:
            self.send_q.put_nowait(None)
        except asyncio.QueueFull:
            pass


class QNode:
    """Full node service."""

    def __init__(self, network: Network, chain: ChainManager,
                 mempool: Mempool, connect_peers: Optional[List[Tuple[str, int]]] = None,
                 seed_hosts: Optional[List[str]] = None,
                 max_peers: int = C.MAX_PEERS,
                 bind_host: str = "0.0.0.0",
                 strict_listen: bool = True):
        self.network = network
        self.chain = chain
        self.mempool = mempool
        self.peers: List[Peer] = []
        self.max_peers = max_peers
        self.connect_peers = list(connect_peers or [])
        self.seed_hosts = list(seed_hosts or [])
        # bind_host controls which interface the P2P listener takes.  The
        # daemon defaults to every interface (a node that cannot accept
        # inbound connections cannot help the network); the web suite's
        # embedded node passes a loopback host so a browser-facing process
        # never opens a port wider than it needs.
        self.bind_host = bind_host
        # strict_listen=True (daemon): a bind failure is a hard error, so an
        # operator never runs a node that silently serves no peers.
        # strict_listen=False (embedded web node): degrade to outbound-only
        # dialing instead of taking the whole UI down over a port clash.
        self.strict_listen = strict_listen
        self.server: Optional[asyncio.AbstractServer] = None
        self.synced = False
        self.listen_failed: Optional[str] = None
        # bounded recently-relayed caches (LRU by insertion order)
        self._known_txs: OrderedDict[str, float] = OrderedDict()
        self._known_blocks: OrderedDict[str, float] = OrderedDict()
        self._known_limit = 50_000
        # peer address book (discovered peers to dial)
        self._known_addrs: OrderedDict[Tuple[str, int], float] = OrderedDict()
        self._banned: Dict[str, Tuple[float, str]] = {}
        self._dialing: Set[Tuple[str, int]] = set()
        self._stop = asyncio.Event()
        self._stop_wait_task: Optional[asyncio.Task] = None
        self._housekeeping_task: Optional[asyncio.Task] = None
        self._sync_task: Optional[asyncio.Task] = None
        self._announce_task: Optional[asyncio.Task] = None
        self._peer_retry_task: Optional[asyncio.Task] = None
        self.on_block_connected = None   # callback(Block)
        self.on_tx_accepted = None       # callback(Transaction)
        self.on_reorg = None             # callback(new_tip, old_tip)
        # sync progress tracking
        self._last_sync_progress = time.time()
        self._headers_requested_at = 0.0
        # blocks requested but never delivered (stall detection)
        self._requested: OrderedDict[bytes, float] = OrderedDict()
        self.start_time = time.time()
        self.stats = {
            "blocks_received": 0, "blocks_relayed": 0, "txs_received": 0,
            "txs_relayed": 0, "peers_connected": 0, "peers_banned": 0,
            "rejected_blocks": 0, "rejected_txs": 0,
        }
        self._load_bans()

    # ------------------------------------------------------------------
    async def start(self):
        if self.bind_host is not None:
            sock = None
            try:
                # The socket is created here (instead of
                # reuse_address=True) so Windows gets SO_EXCLUSIVEADDRUSE:
                # with SO_REUSEADDR another local process could bind the P2P
                # port too and quietly take the node's place in the network.
                sock = listener_socket(self.bind_host, self.network.p2p_port)
                self.server = await asyncio.start_server(
                    self._handle_connection, sock=sock, backlog=64)
                sock = None            # start_server owns it now
            except OSError as e:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                if self.strict_listen:
                    raise
                self.listen_failed = (
                    f"p2p listen on {self.bind_host}:{self.network.p2p_port} "
                    f"failed: {e} (continuing outbound-only)")
                logger.warning(self.listen_failed)
                self.server = None
        if self.server is not None:
            logger.info("p2p listening on %s:%d", self.bind_host,
                        self.network.p2p_port)
        for host, port in self.connect_peers:
            self._add_known_addr(host, port)
            asyncio.ensure_future(self._connect_peer(host, port))
        # an explicitly configured peer may not be listening yet (the other
        # node started a moment later), so retry it on a short backoff instead
        # of waiting for the next discovery sweep
        self._peer_retry_task: Optional[asyncio.Task] = None
        if self.connect_peers:
            self._peer_retry_task = asyncio.ensure_future(
                self._retry_configured_peers())
        self._stop_wait_task = asyncio.ensure_future(self._stop.wait())
        self._housekeeping_task = asyncio.ensure_future(self._housekeeping())
        self._sync_task = asyncio.ensure_future(self._sync_driver())
        self._announce_task = asyncio.ensure_future(
            self._flush_announcements())

    async def stop(self):
        """Graceful shutdown that actually terminates.

        Order matters: kick every peer first (their writer tasks close the
        sockets, which unblocks the read loops), then close the server and
        bound the wait so no handler can hang shutdown.
        """
        self._stop.set()
        if self._stop_wait_task:
            self._stop_wait_task.cancel()
        # 1. kick peers: closes write sides, remote read() returns EOF
        for p in list(self.peers):
            p.kick()
        # 2. close our server socket
        if self.server:
            self.server.close()
        # 3. give writer tasks a moment to flush and exit
        for p in list(self.peers):
            if p.writer_task:
                try:
                    await asyncio.wait_for(asyncio.shield(p.writer_task),
                                           timeout=2.0)
                except Exception:
                    p.writer_task.cancel()
        # 4. bounded wait for handler tasks (deadlock-proof)
        if self.server:
            try:
                await asyncio.wait_for(asyncio.shield(self.server.wait_closed()),
                                       timeout=3.0)
            except Exception:
                pass
        for t in (self._housekeeping_task, self._sync_task,
                  self._announce_task, self._peer_retry_task):
            if t:
                t.cancel()
                try:
                    await asyncio.wait_for(asyncio.shield(t), timeout=2.0)
                except Exception:
                    pass
        # 5. hard close remaining transports
        for p in list(self.peers):
            try:
                p.writer.close()
            except Exception:
                pass
        self.peers.clear()

    # ------------------------------------------------------------------
    # peer address book / ban list
    # ------------------------------------------------------------------
    def _add_known_addr(self, host: str, port: int):
        if not host or not (1 <= int(port) <= 65535):
            return
        key = (str(host), int(port))
        if self.is_banned(f"{key[0]}:{key[1]}"):
            return
        self._known_addrs[key] = time.time()
        while len(self._known_addrs) > C.KNOWN_ADDR_LIMIT:
            self._known_addrs.popitem(last=False)

    def is_banned(self, addr: str) -> bool:
        entry = self._banned.get(addr)
        if entry is None:
            if self.chain.store is not None and self.chain.store.is_banned(addr):
                return True
            return False
        until, _why = entry
        if until <= time.time():
            self._banned.pop(addr, None)
            if self.chain.store is not None:
                self.chain.store.ban_peer(addr, 0, 0)
            return False
        return True

    def ban(self, peer: Peer, reason: str = ""):
        """Disconnect a peer and remember the ban across restarts."""
        addr = peer.addr
        if addr == "?":
            hp = peer.host_port
            addr = f"{hp[0]}:{hp[1]}" if hp else addr
        until = time.time() + C.BAN_DURATION
        self._banned[addr] = (until, reason)
        while len(self._banned) > C.MAX_BANNED:
            self._banned.pop(next(iter(self._banned)))
        self.stats["peers_banned"] += 1
        if self.chain.store is not None:
            try:
                self.chain.store.ban_peer(addr, until, peer.score, reason)
            except Exception:
                pass
        logger.warning("banned %s (%s, score %d)", addr, reason, peer.score)
        peer.kick()

    def _load_bans(self):
        if self.chain.store is None:
            return
        try:
            import time as _t
            n = 0
            for addr, until, score, reason in self.chain.store.list_bans():
                if until > _t.time():
                    self._banned[addr] = (until, reason or "")
                    n += 1
            if n:
                logger.info("loaded %d active peer bans", n)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # connection handling
    # ------------------------------------------------------------------
    @staticmethod
    def _close_writer(writer) -> None:
        try:
            writer.close()
        except Exception:
            pass

    def _refuse_connection(self, ip: str, inbound: bool) -> Optional[str]:
        """None when a new connection may be served, else the refusal reason.

        The ceiling is enforced BEFORE the handshake, so a connection flood
        costs one accept plus one close instead of a Peer object, a writer
        task and up to MAX_FRAME_BUFFER of buffered bytes per socket.

        Outbound slots are reserved: with the per-IP cap alone, 16 distinct
        hosts could hold every one of MAX_PEERS slots and the node would be
        unable to dial the peers it needs to sync from (a cheap eclipse).
        """
        if len(self.peers) >= self.max_peers:
            return f"peer limit reached ({self.max_peers})"
        if not inbound:
            return None
        inbound_count = sum(1 for p in self.peers if p.inbound)
        cap = max(1, self.max_peers - C.RESERVED_OUTBOUND_SLOTS)
        if inbound_count >= cap:
            return (f"inbound limit reached ({cap}); "
                    f"{C.RESERVED_OUTBOUND_SLOTS} slots reserved for outbound")
        if ip:
            same_ip = sum(1 for p in self.peers if p.inbound and p.ip == ip)
            if same_ip >= C.MAX_PEERS_PER_IP:
                return (f"per-IP inbound limit reached "
                        f"({C.MAX_PEERS_PER_IP} connections from {ip})")
        return None

    async def _connect_peer(self, host: str, port: int):
        """Dial a peer and then SERVE it for the life of the connection.

        This coroutine only returns when the peer disconnects, so it must
        always be scheduled as a task (`asyncio.ensure_future`) and never
        awaited from the caller's own flow.
        """
        key = (host, int(port))
        if key in self._dialing:
            return
        if self.is_banned(f"{host}:{port}"):
            return
        self._dialing.add(key)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10)
        except Exception as e:
            logger.debug("connect %s:%s failed: %s", host, port, e)
            return
        finally:
            self._dialing.discard(key)
        if self._stop.is_set():
            try:
                writer.close()
            except Exception:
                pass
            return
        await self._handle_connection(reader, writer, inbound=False)

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter,
                                 inbound: bool = True):
        peername = writer.get_extra_info("peername")
        ip = peername[0] if peername else ""
        if peername and self.is_banned(f"{ip}:{peername[1]}"):
            self._close_writer(writer)
            return
        refusal = self._refuse_connection(ip, inbound)
        if refusal:
            logger.debug("refusing %s connection from %s: %s",
                         "inbound" if inbound else "outbound",
                         ip or "?", refusal)
            self._close_writer(writer)
            return
        peer = Peer(reader, writer, self, inbound)
        self.peers.append(peer)
        self.stats["peers_connected"] += 1
        peer.writer_task = asyncio.ensure_future(peer._writer_loop())
        try:
            await self._handshake(peer)
            await self._message_loop(peer)
        except PeerMisbehaved as e:
            logger.info("dropping peer %s: %s", peer.addr, e)
        except (ConnectionError, asyncio.IncompleteReadError, ValueError,
                BufferError, asyncio.TimeoutError, OSError) as e:
            logger.debug("peer %s dropped: %s", peer.addr, e)
        except asyncio.CancelledError:
            pass
        except Exception as e:  # defensive: never let a handler crash the task
            logger.warning("peer %s handler error: %r", peer.addr, e)
        finally:
            peer.kick()
            if peer.writer_task:
                try:
                    await asyncio.wait_for(asyncio.shield(peer.writer_task),
                                           timeout=1.0)
                except Exception:
                    peer.writer_task.cancel()
            try:
                if peer in self.peers:
                    self.peers.remove(peer)
            except ValueError:
                pass
            try:
                writer.close()
            except Exception:
                pass

    def version_payload(self) -> dict:
        return {
            "version": C.PROTOCOL_VERSION,
            "network": self.network.name,
            "user_agent": C.USER_AGENT,
            "height": self.chain.height(),
            "best": self.chain.tip_hash().hex(),
            "timestamp": int(time.time()),
        }

    async def announce(self, peer: Peer, force: bool = False) -> bool:
        """Re-advertise our height to `peer` when it has changed.

        A peer's view of our height is a snapshot from its `version`
        message.  Without a refresh it goes stale the moment we mine or sync
        a block, and a node that was level at handshake time then falls
        behind would never notice - the sync driver compares the chain tip
        against `peer.best_height` and would report itself synced forever.

        The refresh is coalesced, because a fast sync must not turn into one
        `version` frame per block.  A suppressed refresh is remembered and
        flushed by `_flush_announcements` once the burst settles, so the peer
        always learns our FINAL height - without that, a node that mined a
        dozen blocks inside one throttle window would leave the other side
        convinced it is level and the two would never sync again.
        """
        now = time.time()
        h = self.chain.height()
        if peer.announced_height == h and not force:
            return False
        if not force and now - peer.last_announce < ANNOUNCE_MIN_INTERVAL:
            peer.announce_pending = True
            return False
        peer.last_announce = now
        peer.announced_height = h
        peer.announce_pending = False
        peer.try_send("version", self.version_payload())
        return True

    async def broadcast_height(self):
        for p in list(self.peers):
            if p.veracked and not p.closing:
                await self.announce(p)

    async def _retry_configured_peers(self):
        """Keep trying the peers named by --connect until they answer.

        A node started fractionally before its peer would otherwise report
        itself synced and stay idle until the next discovery sweep, which is
        the difference between a connected network and a silent one at
        launch.
        """
        delay = PEER_RETRY_MIN_INTERVAL
        try:
            while not self._stop.is_set():
                await asyncio.sleep(delay)
                delay = min(delay * 2, PEER_RETRY_MAX_INTERVAL)
                if any(not p.inbound for p in self.peers):
                    continue
                for host, port in self.connect_peers:
                    if (host, port) in {(p.host_port) for p in self.peers}:
                        continue
                    self._add_known_addr(host, port)
                    asyncio.ensure_future(self._connect_peer(host, port))
                    if not any(not p.inbound for p in self.peers):
                        delay = PEER_RETRY_MIN_INTERVAL
        except asyncio.CancelledError:
            pass

    async def _flush_announcements(self):
        """Deliver the announcements that `announce` coalesced away."""
        try:
            while not self._stop.is_set():
                await asyncio.sleep(ANNOUNCE_FLUSH_INTERVAL)
                for p in list(self.peers):
                    if p.veracked and not p.closing and p.announce_pending:
                        await self.announce(p)
        except asyncio.CancelledError:
            pass

    async def _handshake(self, peer: Peer):
        # send our version; the peer's version arrives through the normal
        # frame loop (_on_version completes the handshake and triggers
        # header requests when the peer is ahead)
        peer.announced_height = self.chain.height()
        peer.last_announce = time.time()
        await peer.send("version", self.version_payload())
        await peer.send("getaddr", {})

    # ------------------------------------------------------------------
    async def _message_loop(self, peer: Peer):
        """Read frames until EOF or node stop (read races the stop event so
        shutdown is never blocked by a silent peer)."""
        while not self._stop.is_set():
            read_task = asyncio.ensure_future(peer.reader.read(65536))
            done, _pending = await asyncio.wait(
                {read_task, self._stop_wait_task},
                return_when=asyncio.FIRST_COMPLETED)
            if self._stop.is_set():
                read_task.cancel()
                break
            data = read_task.result()
            if not data:
                break
            try:
                peer.reader_buf.feed(data)
            except BufferError:
                peer.penalise(20, "frame buffer overflow")
                raise PeerMisbehaved("frame buffer overflow")
            while True:
                frame = peer.reader_buf.next_frame()
                if frame is None:
                    break
                command, payload = frame
                if not peer.allow_message():
                    peer.penalise(5, "message rate limit exceeded")
                    raise PeerMisbehaved("message rate limit exceeded")
                peer.last_seen = time.time()
                try:
                    await self._dispatch(peer, command, payload)
                except PeerMisbehaved:
                    raise
                except (ConnectionError, asyncio.QueueFull, OSError):
                    raise
                except _DisconnectPeer as e:
                    logger.debug("disconnecting %s: %s", peer.addr, e)
                    return
                except Exception as e:
                    # a malformed payload must never kill the node
                    logger.debug("handler %s from %s failed: %r",
                                 command, peer.addr, e)

    # ------------------------------------------------------------------
    async def _dispatch(self, peer: Peer, command: str, payload: dict):
        if not isinstance(payload, dict):
            raise _DisconnectPeer("non-object payload")
        handler = getattr(self, f"_on_{command}", None)
        if handler is None:
            return
        await handler(peer, payload)

    # ------------------------------------------------------------------
    # periodic tasks
    # ------------------------------------------------------------------
    async def _housekeeping(self):
        """Keepalive pings, idle pruning, discovery and reconnects."""
        try:
            while not self._stop.is_set():
                await asyncio.sleep(min(C.PEER_PING_INTERVAL,
                                        C.PEER_RECONNECT_INTERVAL))
                now = time.time()
                for p in list(self.peers):
                    if now - p.last_seen > C.PEER_IDLE_TIMEOUT:
                        logger.debug("peer %s idle, dropping", p.addr)
                        p.kick()
                        continue
                    if p.veracked and now - p.last_ping_sent > C.PEER_PING_INTERVAL:
                        p.last_ping_sent = now
                        p.try_send("ping", {"nonce": int(now)})
                    if p.veracked and now - p.last_announce > C.PEER_ANNOUNCE_INTERVAL:
                        p.last_announce = now
                        await self.announce(p)
                for host in self.seed_hosts:
                    try:
                        infos = await asyncio.get_running_loop().getaddrinfo(
                            host, self.network.p2p_port, family=socket.AF_INET)
                        for info in infos[:8]:
                            self._add_known_addr(info[4][0], info[4][1])
                    except Exception:
                        pass
                outbound = sum(1 for p in self.peers if not p.inbound)
                if outbound < C.TARGET_OUTBOUND_PEERS and not self._stop.is_set():
                    want = C.TARGET_OUTBOUND_PEERS - outbound
                    dialed = {p.host_port for p in self.peers}
                    # _connect_peer claims the in-flight slot itself; claiming
                    # it here would make it see its own key and skip the dial
                    dialing = set(self._dialing)
                    for (host, port), _ts in list(self._known_addrs.items()):
                        if want <= 0:
                            break
                        if (host, port) in dialed or (host, port) in dialing:
                            continue
                        want -= 1
                        asyncio.ensure_future(self._connect_peer(host, port))
        except asyncio.CancelledError:
            pass

    async def _sync_driver(self):
        """Continuous headers-first sync with stall detection."""
        try:
            while not self._stop.is_set():
                await asyncio.sleep(C.SYNC_TICK_INTERVAL)
                self._expire_stalled_requests()
                ahead = [p for p in self.peers
                         if p.veracked and p.best_height > self.chain.height()]
                if ahead:
                    if self.synced:
                        self.synced = False
                    if time.time() - self._headers_requested_at > \
                            C.STALLED_SYNC_TIMEOUT:
                        await self._request_headers(ahead[0])
                        self._request_missing_blocks()
                elif not self._requested:
                    if not self.synced:
                        self.synced = True
                        logger.info("synced at height %d", self.chain.height())
        except asyncio.CancelledError:
            pass

    def _expire_stalled_requests(self):
        """Re-ask for blocks a peer promised but never delivered."""
        cutoff = time.time() - C.STALLED_SYNC_TIMEOUT
        stale = [h for h, ts in self._requested.items() if ts < cutoff]
        for h in stale:
            self._requested.pop(h, None)
        for p in self.peers:
            p.requested -= set(stale)
        if stale:
            logger.debug("re-requesting %d stalled blocks", len(stale))

    # ------------------------------------------------------------------
    # command handlers
    # ------------------------------------------------------------------
    async def _on_version(self, peer: Peer, payload: dict):
        """Handle a version message.

        `verack` is answered exactly once per connection.  A later `version`
        from the same peer is a HEIGHT REFRESH (see `announce`), and
        answering it with another `verack` would start a version/verack ping
        pong that ends with the rate limiter dropping both peers.
        """
        if payload.get("network") != self.network.name:
            peer.penalise(C.BAN_SCORE_THRESHOLD, "wrong network")
            raise PeerMisbehaved(
                f"network mismatch: {payload.get('network')!r} != "
                f"{self.network.name!r}")
        pv = int(payload.get("version", 0))
        if pv < C.PROTOCOL_VERSION:
            raise PeerMisbehaved(f"protocol version {pv} too old")
        peer.peer_version = payload
        try:
            peer.best_height = int(payload.get("height", -1))
        except (TypeError, ValueError):
            peer.best_height = -1
        if payload.get("timestamp"):
            try:
                skew = abs(int(time.time()) - int(payload["timestamp"]))
                if skew > 7 * 24 * 3600:
                    peer.penalise(20, "gross clock skew")
            except (TypeError, ValueError):
                pass
        first_handshake = not peer.veracked
        if first_handshake:
            peer.veracked = True
            await peer.send("verack", {})
        self._note_sync_progress()
        if peer.best_height > self.chain.height():
            await self._request_headers(peer)

    async def _on_verack(self, peer: Peer, payload: dict):
        peer.veracked = True
        self._note_sync_progress()
        # The handshake is complete on both sides, so both heights are now
        # known.  Re-advertise ours (in case we moved during the handshake)
        # and re-evaluate the sync direction with fresh numbers.
        await self.announce(peer, force=True)
        if peer.best_height > self.chain.height():
            await self._request_headers(peer)

    async def _on_ping(self, peer: Peer, payload: dict):
        await peer.send("pong", payload)

    async def _on_pong(self, peer: Peer, payload: dict):
        pass

    # ------------------------------------------------------------------
    def _locator(self) -> List[str]:
        """Sparse block locator: the last 11 hashes, then exponentially
        sparser back to genesis (Bitcoin-style)."""
        hashes = []
        height = self.chain.height()
        step = 1
        h = height
        while h >= 0:
            blk = self.chain.get_block_by_height(h)
            if blk is None:
                break
            hashes.append(blk.hash.hex())
            if len(hashes) >= 11:
                step *= 2
            h -= step
            if len(hashes) > 128:
                break
        if hashes and hashes[-1] != self.chain.genesis.hash.hex():
            hashes.append(self.chain.genesis.hash.hex())
        return hashes

    async def _request_headers(self, peer: Peer):
        self._headers_requested_at = time.time()
        self._note_sync_progress()
        await peer.send("getheaders", {
            "locator": self._locator(),
            "height": self.chain.height(),
        })

    def _note_sync_progress(self):
        self._last_sync_progress = time.time()

    def _request_missing_blocks(self, limit: int = C.MAX_GETDATA_BLOCKS):
        """After a stall, re-anchor on the best peer and ask for headers
        again from our own tip so the download restarts cleanly."""
        if not self._requested:
            return
        peer = self._best_peer()
        if peer is None:
            return
        peer.try_send("getheaders", {"locator": self._locator(),
                                     "height": self.chain.height()})

    def _best_peer(self) -> Optional[Peer]:
        cand = [p for p in self.peers
                if p.veracked and not p.closing and len(p.send_q) < 200]
        if not cand:
            return None
        return max(cand, key=lambda p: p.best_height)

    async def _on_getheaders(self, peer: Peer, payload: dict):
        # serve headers after the highest locator hash we know
        best = -1
        for h in (payload.get("locator") or [])[:256]:
            try:
                blk = self.chain.get_block(bytes.fromhex(h))
            except (ValueError, TypeError):
                continue
            if blk is not None:
                best = max(best, blk.height)
        headers = []
        height = best + 1
        while len(headers) < C.MAX_HEADERS:
            blk = self.chain.get_block_by_height(height)
            if blk is None:
                break
            headers.append(blk.header.serialize().hex())
            height += 1
        await peer.send("headers", {"headers": headers})

    async def _on_getblocks(self, peer: Peer, payload: dict):
        """Serve a locator-driven batch of full blocks (used by peers that
        skip the headers-first walk)."""
        best = -1
        for h in (payload.get("locator") or [])[:256]:
            try:
                blk = self.chain.get_block(bytes.fromhex(h))
            except (ValueError, TypeError):
                continue
            if blk is not None:
                best = max(best, blk.height)
        sent = 0
        for height in range(best + 1, self.chain.height() + 1):
            if sent >= C.MAX_GETDATA_BLOCKS:
                break
            blk = self.chain.get_block_by_height(height)
            if blk is None:
                break
            if not peer.try_send("block", {"block": blk.serialize().hex()}):
                break
            sent += 1

    async def _on_headers(self, peer: Peer, payload: dict):
        """Request the bodies of unknown headers, in bounded batches.

        The batch must be a CONTIGUOUS chain anchored in a block we already
        have: the first header has to extend a known block and every later
        header has to extend its predecessor, at the next height, with a
        valid proof of work.  Without those checks an unsolicited `headers`
        message could aim the sync driver at an arbitrary chain and inflate
        the peer's advertised height, turning every frame into a getdata
        round for blocks that can never connect.  An honest peer always
        passes: `_on_getheaders` serves exactly this shape.
        """
        raw = (payload.get("headers") or [])[:C.MAX_HEADERS]
        wanted: List[bytes] = []
        prev_hash: Optional[bytes] = None
        prev_height: Optional[int] = None
        for hh in raw:
            try:
                hdr = BlockHeader.deserialize(bytes.fromhex(hh))
            except (ValueError, TypeError, AttributeError):
                peer.penalise(5, "malformed header")
                raise PeerMisbehaved("malformed header in headers message")
            if prev_hash is None:
                parent = self.chain.get_block(hdr.prev_hash)
                if parent is None or hdr.height != parent.height + 1:
                    peer.penalise(C.BAN_SCORE_THRESHOLD // 2,
                                  "headers do not extend a known block")
                    raise PeerMisbehaved(
                        "header batch does not extend a known block")
            elif hdr.prev_hash != prev_hash or hdr.height != prev_height + 1:
                peer.penalise(C.BAN_SCORE_THRESHOLD // 2,
                              "headers are not a contiguous chain")
                raise PeerMisbehaved("header batch is not contiguous")
            try:
                if not pow_mod.check_pow(hdr.serialize(), hdr.bits):
                    peer.penalise(C.BAN_SCORE_THRESHOLD,
                                  "header fails its own PoW")
                    raise PeerMisbehaved("header with invalid proof of work")
            except ValueError:
                peer.penalise(C.BAN_SCORE_THRESHOLD,
                              "header with a malformed target")
                raise PeerMisbehaved("header with malformed compact target")
            # BlockHeader.hash is a method (Block.hash is a property)
            prev_hash = hdr.hash()
            prev_height = hdr.height
            if self.chain.store is not None and \
                    self.chain.store.block_exists(prev_hash):
                continue
            if prev_hash in self._requested:
                continue
            wanted.append(prev_hash)
        self._note_sync_progress()
        if prev_height is not None:
            # the peer's real height, taken from the chain it just proved it
            # has, instead of the inflated hop-count guess used before
            peer.best_height = max(peer.best_height, prev_height)
        if not wanted:
            if self.chain.height() >= max((p.best_height for p in self.peers),
                                           default=0):
                self.synced = True
            return
        batch = wanted[:C.MAX_GETDATA_BLOCKS]
        now = time.time()
        for h in batch:
            self._requested[h] = now
            peer.requested.add(h)
        peer.try_send("getdata", {"blocks": [h.hex() for h in batch]})
        if len(wanted) > len(batch) or len(raw) >= C.MAX_HEADERS:
            # more headers are waiting: keep the walk going from our tip
            peer.try_send("getheaders", {"locator": self._locator(),
                                         "height": self.chain.height()})

    async def _on_getdata(self, peer: Peer, payload: dict):
        for h in (payload.get("blocks") or [])[:C.MAX_INV]:
            try:
                bh = bytes.fromhex(h)
            except (ValueError, TypeError):
                continue
            blk = self.chain.get_block(bh)
            if blk is not None:
                if not peer.try_send("block", {"block": blk.serialize().hex()}):
                    return
            else:
                # answer with notfound so the requester stops waiting
                peer.try_send("notfound", {"blocks": [h]})
        for t in (payload.get("txs") or [])[:C.MAX_INV]:
            try:
                th = bytes.fromhex(t)
            except (ValueError, TypeError):
                continue
            tx = self.mempool.get_tx(th)
            if tx is not None:
                if not peer.try_send("tx", {"tx": tx.serialize().hex()}):
                    return
            else:
                peer.try_send("notfound", {"txs": [t]})

    async def _on_notfound(self, peer: Peer, payload: dict):
        """A peer could not serve an item; stop waiting for it."""
        for h in (payload.get("blocks") or []):
            try:
                hb = bytes.fromhex(h)
            except (ValueError, TypeError):
                continue
            self._requested.pop(hb, None)
            peer.requested.discard(hb)
        for t in (payload.get("txs") or []):
            try:
                ht = bytes.fromhex(t)
            except (ValueError, TypeError):
                continue
            peer.requested.discard(ht)

    async def _on_inv(self, peer: Peer, payload: dict):
        blocks = (payload.get("blocks") or [])[:C.MAX_INV]
        txs = (payload.get("txs") or [])[:C.MAX_INV]
        want_blocks = []
        for h in blocks:
            if h in self._known_blocks:
                continue
            try:
                bh = bytes.fromhex(h)
            except (ValueError, TypeError):
                continue
            if self.chain.store is None or not self.chain.store.block_exists(bh):
                want_blocks.append(h)
        want_txs = []
        for t in txs:
            if t in self._known_txs:
                continue
            want_txs.append(t)
        if want_blocks or want_txs:
            await peer.send("getdata", {"blocks": want_blocks[:C.MAX_INV],
                                        "txs": want_txs[:C.MAX_INV]})

    async def _on_block(self, peer: Peer, payload: dict):
        try:
            blk = Block.deserialize(bytes.fromhex(payload["block"]))
        except (ValueError, KeyError, TypeError):
            peer.penalise(1, "malformed block")
            return
        bh = blk.hash
        self._requested.pop(bh, None)
        peer.requested.discard(bh)
        if blk.header.height > peer.best_height:
            peer.best_height = blk.header.height
        peer.synced_blocks += 1
        if blk.header.height > self.chain.height() + C.MAX_ORPHAN_BLOCKS + 1:
            # too far ahead: request headers instead of holding garbage
            peer.penalise(5, "block far ahead of chain")
            await self._request_headers(peer)
            return
        await self.submit_block(blk, broadcast=True, exclude=peer)

    async def _on_tx(self, peer: Peer, payload: dict):
        try:
            tx = Transaction.deserialize(bytes.fromhex(payload["tx"]))
        except (ValueError, KeyError, TypeError):
            peer.penalise(1, "malformed transaction")
            return
        self.stats["txs_received"] += 1
        await self.submit_tx(tx, broadcast=True, exclude=peer)

    async def _on_mempool(self, peer: Peer, payload: dict):
        txs = [t.txid().hex() for t in self.mempool.all_txs()]
        # never push more than one inv frame's worth at a peer at once
        await peer.send("inv", {"txs": txs[:C.MAX_INV]})

    # ------------------------------------------------------------------
    # peer discovery
    # ------------------------------------------------------------------
    async def _on_getaddr(self, peer: Peer, payload: dict):
        now = time.time()
        entries = []
        for p in self.peers:
            if p is peer or not p.veracked:
                continue
            hp = p.host_port
            if hp:
                entries.append({"host": hp[0], "port": hp[1]})
        for (host, port), ts in list(self._known_addrs.items()):
            if now - ts > 3600:
                continue
            entries.append({"host": host, "port": port})
            if len(entries) >= C.MAX_ADDR_RELAY:
                break
        # a node never advertises more than half its capacity in one message
        await peer.send("addr",
                        {"addrs": entries[:C.MAX_ADDR_RELAY // 2]})

    async def _on_addr(self, peer: Peer, payload: dict):
        added = 0
        # accept up to twice what we would advertise before scoring, so the
        # threshold below is reachable
        for e in (payload.get("addrs") or [])[:2 * C.MAX_ADDR_RELAY]:
            try:
                host = str(e["host"])
                port = int(e["port"])
            except (KeyError, TypeError, ValueError):
                continue
            if not (1 <= port <= 65535) or not host or len(host) > 255:
                continue
            if (host, port) in self._known_addrs:
                continue
            self._add_known_addr(host, port)
            added += 1
        # Unsolicited address spam is a classic eclipse vector.  We advertise
        # at most MAX_ADDR_RELAY/2 addresses per message, so a peer that
        # hands us more brand-new addresses than we would ever serve is not
        # one we keep.  Half that is merely suspicious and only scores.
        if added > C.MAX_ADDR_RELAY:
            peer.penalise(C.BAN_SCORE_THRESHOLD, "addr flood")
            raise PeerMisbehaved(
                f"addr flood: {added} new addresses in one message")
        if added > C.MAX_ADDR_RELAY // 8:
            peer.penalise(20, "large addr message")

    # ------------------------------------------------------------------
    # relayed-id caches (bounded)
    # ------------------------------------------------------------------
    def _remember(self, cache: OrderedDict, key: str):
        cache[key] = time.time()
        while len(cache) > self._known_limit:
            cache.popitem(last=False)

    def forget(self, block_hash: bytes):
        """Drop a block from the relayed cache (after a reorg the block may
        become acceptable again)."""
        self._known_blocks.pop(block_hash.hex(), None)

    # ------------------------------------------------------------------
    # submission (used by peers, RPC and the miner alike)
    # ------------------------------------------------------------------
    async def submit_block(self, block: Block, broadcast: bool = True,
                           exclude: Optional[Peer] = None) -> bool:
        h = block.hash.hex()
        if self.chain.store and self.chain.store.block_exists(block.hash):
            return False
        try:
            result = self.chain.connect_block(block)
        except BlockValidationError as e:
            self.stats["rejected_blocks"] += 1
            logger.info("rejected block %s: %s", h[:16], e)
            if exclude is not None:
                exclude.penalise(2, "invalid block")
            return False
        except Exception as e:  # never let consensus bugs kill a handler
            logger.warning("block connect error %s: %r", h[:16], e)
            return False
        if result.connected:
            self.stats["blocks_received"] += 1
            self._remember(self._known_blocks, h)
            logger.info("connected block %d %s", block.height, h[:16])
            self.mempool.on_new_block(block)
            self._note_sync_progress()
            if self.on_block_connected:
                try:
                    self.on_block_connected(block)
                except Exception:
                    pass
            if broadcast:
                self.stats["blocks_relayed"] += 1
                await self.broadcast("inv", {"blocks": [h]}, exclude=exclude)
            await self.broadcast_height()
            # consider_reorg() invokes chain.on_reorg (this node's
            # reorg_callback) itself when the fork choice actually changes
            self.chain.consider_reorg()
            return True
        if result.duplicate:
            return False
        if result.orphan:
            self.stats["rejected_blocks"] += 1
            # we are missing the parent: ask the sending peer for headers
            if exclude is not None:
                await self._request_headers(exclude)
        return False

    async def submit_tx(self, tx: Transaction, broadcast: bool = True,
                        exclude: Optional[Peer] = None) -> Tuple[bool, str]:
        txid = tx.txid().hex()
        if txid in self._known_txs:
            return True, "already known"
        try:
            self.mempool.add_tx(tx)
        except TxValidationError as e:
            self.stats["rejected_txs"] += 1
            if exclude is not None:
                exclude.penalise(1, "invalid transaction")
            return False, str(e)
        self._remember(self._known_txs, txid)
        if self.on_tx_accepted:
            try:
                self.on_tx_accepted(tx)
            except Exception:
                pass
        if broadcast:
            self.stats["txs_relayed"] += 1
            await self.broadcast("inv", {"txs": [txid]}, exclude=exclude)
        return True, "accepted"

    # ------------------------------------------------------------------
    async def broadcast(self, command: str, payload: dict,
                        exclude: Optional[Peer] = None):
        """Relay to all handshaked peers; each peer has its own send queue
        so one slow peer cannot stall the others."""
        for peer in list(self.peers):
            if peer is exclude or peer.closing:
                continue
            if not (peer.veracked or peer.peer_version):
                continue
            peer.try_send(command, payload)

    def reorg_callback(self, new_tip: Block, old_tip: Block):
        """ChainManager hook: return transactions from disconnected blocks
        to the mempool and re-broadcast them."""
        try:
            disconnected = self.chain.disconnected_blocks(old_tip, new_tip)
        except Exception:
            disconnected = []
        revived = []
        for blk in disconnected:
            for tx in blk.transactions:
                if tx.is_coinbase:
                    continue
                revived.append(tx)
        for blk in disconnected:
            self.forget(blk.hash)
        if revived:
            self.mempool.readd_many(revived)
        else:
            self.mempool.resync()
        if self.on_reorg:
            try:
                self.on_reorg(new_tip, old_tip)
            except Exception:
                pass
        self.synced = False

    def best_chain_info(self) -> dict:
        return {
            "height": self.chain.height(),
            "best": self.chain.tip_hash().hex(),
            "synced": self.synced,
            "peers": len(self.peers),
        }

    def peer_info(self) -> List[dict]:
        out = []
        for p in list(self.peers):
            hp = p.host_port
            out.append({
                "addr": f"{hp[0]}:{hp[1]}" if hp else "?",
                "inbound": p.inbound,
                "version": p.peer_version.get("version") if p.peer_version else None,
                "user_agent": p.peer_version.get("user_agent") if p.peer_version else None,
                "subver": p.peer_version.get("network") if p.peer_version else None,
                "best_height": p.best_height,
                "start_height": p.start_height,
                "last_seen": p.last_seen,
                "score": p.decayed_score(),
                "queued": p.send_q.qsize(),
            })
        return out


class _DisconnectPeer(Exception):
    """Internal: close this connection without banning the peer."""

"""
Peer-to-peer node service (asyncio TCP).

Responsibilities:
  * handshake (version/verack) and peer registry with rate limiting
  * headers-first initial block download with a continuous sync driver
  * block/tx relay with inv/getdata (non-blocking per-peer send queues)
  * peer discovery (getaddr/addr), keepalive pings, idle pruning,
    periodic reconnect toward TARGET_OUTBOUND_PEERS
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
from typing import Dict, List, Optional, Tuple

from qeuph import constants as C
from qeuph.config import Network
from qeuph.core.block import Block, BlockHeader
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.tx import Transaction
from qeuph.core.validation import BlockValidationError, TxValidationError
from qeuph.network.protocol import FrameReader, encode_frame

logger = logging.getLogger("qeuph.node")


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
        # token-bucket rate limit
        self._tokens = float(C.PEER_MSG_BURST)
        self._last_token = time.time()
        # outbound send queue + writer task
        self.send_q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self.writer_task: Optional[asyncio.Task] = None
        self.closing = False

    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    async def send(self, command: str, payload: dict):
        """Queue a frame; the peer's writer task drains it.  Raises
        asyncio.QueueFull for persistently slow peers."""
        frame = encode_frame(command, payload, self.node.network.magic)
        if self.closing:
            return
        self.send_q.put_nowait(frame)      # QueueFull propagates to caller

    def try_send(self, command: str, payload: dict) -> bool:
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
                 seed_hosts: Optional[List[str]] = None):
        self.network = network
        self.chain = chain
        self.mempool = mempool
        self.peers: List[Peer] = []
        self.connect_peers = list(connect_peers or [])
        self.seed_hosts = list(seed_hosts or [])
        self.server: Optional[asyncio.AbstractServer] = None
        self.synced = False
        # bounded recently-relayed caches (LRU by insertion order)
        self._known_txs: OrderedDict[str, float] = OrderedDict()
        self._known_blocks: OrderedDict[str, float] = OrderedDict()
        self._known_limit = 50_000
        # peer address book (discovered peers to dial)
        self._known_addrs: OrderedDict[Tuple[str, int], float] = OrderedDict()
        self._stop = asyncio.Event()
        self._stop_wait_task: Optional[asyncio.Task] = None
        self._housekeeping_task: Optional[asyncio.Task] = None
        self._sync_task: Optional[asyncio.Task] = None
        self.on_block_connected = None   # callback(Block)
        self.on_tx_accepted = None       # callback(Transaction)
        self.on_reorg = None             # callback(new_tip, old_tip)
        # sync progress tracking
        self._last_sync_progress = time.time()
        self._headers_requested_at = 0.0

    # ------------------------------------------------------------------
    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.network.p2p_port,
            reuse_address=True)
        logger.info("p2p listening on %d", self.network.p2p_port)
        # dial the explicitly configured peers right away
        for host, port in self.connect_peers:
            self._add_known_addr(host, port)
            asyncio.ensure_future(self._connect_peer(host, port))
        self._stop_wait_task = asyncio.ensure_future(self._stop.wait())
        self._housekeeping_task = asyncio.ensure_future(self._housekeeping())
        self._sync_task = asyncio.ensure_future(self._sync_driver())

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
                    await asyncio.wait_for(asyncio.shield(p.writer_task), timeout=2.0)
                except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                    p.writer_task.cancel()
        # 4. bounded wait for handler tasks (deadlock-proof)
        if self.server:
            try:
                await asyncio.wait_for(asyncio.shield(self.server.wait_closed()),
                                       timeout=3.0)
            except (asyncio.TimeoutError, Exception):
                pass
        for t in (self._housekeeping_task, self._sync_task):
            if t:
                t.cancel()
                try:
                    await asyncio.wait_for(asyncio.shield(t), timeout=2.0)
                except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                    pass
        # 5. hard close remaining transports
        for p in list(self.peers):
            try:
                p.writer.close()
            except Exception:
                pass
        self.peers.clear()

    # ------------------------------------------------------------------
    # connection handling
    # ------------------------------------------------------------------
    def _add_known_addr(self, host: str, port: int):
        if host in ("0.0.0.0", "::", "127.0.0.1", "localhost") and not port:
            return
        key = (host, port)
        self._known_addrs[key] = time.time()
        while len(self._known_addrs) > C.KNOWN_ADDR_LIMIT:
            self._known_addrs.popitem(last=False)

    async def _connect_peer(self, host: str, port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=10)
        except Exception as e:
            logger.debug("connect %s:%s failed: %s", host, port, e)
            return
        await self._handle_connection(reader, writer, inbound=False)

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter,
                                 inbound: bool = True):
        peer = Peer(reader, writer, self, inbound)
        self.peers.append(peer)
        peer.writer_task = asyncio.ensure_future(peer._writer_loop())
        try:
            await self._handshake(peer)
            await self._message_loop(peer)
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
                    await asyncio.wait_for(asyncio.shield(peer.writer_task), timeout=1.0)
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

    async def _handshake(self, peer: Peer):
        # send our version; the peer's version arrives through the normal
        # frame loop (_on_version completes the handshake and triggers
        # header requests when the peer is ahead)
        await peer.send("version", {
            "version": C.PROTOCOL_VERSION,
            "network": self.network.name,
            "height": self.chain.height(),
            "best": self.chain.tip_hash().hex(),
            "timestamp": int(time.time()),
        })
        # ask the peer for more peers (discovery)
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
                logger.debug("peer %s buffer overflow, dropping", peer.addr)
                return
            while True:
                frame = peer.reader_buf.next_frame()
                if frame is None:
                    break
                command, payload = frame
                if not peer.allow_message():
                    logger.debug("peer %s rate limited, dropping", peer.addr)
                    return
                peer.last_seen = time.time()
                try:
                    await self._dispatch(peer, command, payload)
                except (ConnectionError, asyncio.QueueFull, OSError):
                    raise
                except Exception as e:
                    # a malformed payload must never kill the node
                    logger.debug("handler %s from %s failed: %r",
                                 command, peer.addr, e)

    # ------------------------------------------------------------------
    async def _dispatch(self, peer: Peer, command: str, payload: dict):
        if not isinstance(payload, dict):
            return
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
                # ping + prune silent peers
                for p in list(self.peers):
                    if now - p.last_seen > C.PEER_IDLE_TIMEOUT:
                        logger.debug("peer %s idle, dropping", p.addr)
                        p.kick()
                        continue
                    if now - p.last_ping_sent > C.PEER_PING_INTERVAL:
                        p.last_ping_sent = now
                        p.try_send("ping", {"nonce": int(now)})
                # resolve DNS seeds periodically
                for host in self.seed_hosts:
                    try:
                        infos = await asyncio.get_running_loop().getaddrinfo(
                            host, self.network.p2p_port, family=socket.AF_INET)
                        for info in infos[:8]:
                            self._add_known_addr(info[4][0], info[4][1])
                    except Exception:
                        pass
                # top up outbound connections
                outbound = sum(1 for p in self.peers if not p.inbound)
                if outbound < C.TARGET_OUTBOUND_PEERS and not self._stop.is_set():
                    want = C.TARGET_OUTBOUND_PEERS - outbound
                    dialed = set(p.host_port for p in self.peers)
                    for (host, port), _ts in list(self._known_addrs.items())[:64]:
                        if want <= 0:
                            break
                        if (host, port) in dialed:
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
                ahead = [p for p in self.peers
                         if p.veracked and p.best_height > self.chain.height()]
                if ahead:
                    if self.synced:
                        self.synced = False
                    # request headers when idle or stalled
                    if time.time() - self._headers_requested_at > \
                            C.STALLED_SYNC_TIMEOUT:
                        await self._request_headers(ahead[0])
                else:
                    if not self.synced:
                        self.synced = True
                        logger.info("synced at height %d", self.chain.height())
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # command handlers
    # ------------------------------------------------------------------
    async def _on_version(self, peer: Peer, payload: dict):
        if payload.get("network") != self.network.name:
            raise ValueError("network mismatch")
        pv = int(payload.get("version", 0))
        if pv > C.PROTOCOL_VERSION:
            # future peer: we stay compatible at version 1
            pass
        if pv < C.PROTOCOL_VERSION:
            raise ValueError(f"protocol version {pv} too old")
        peer.peer_version = payload
        peer.best_height = int(payload.get("height", -1))
        await peer.send("verack", {})
        self._note_sync_progress()
        if peer.best_height > self.chain.height():
            await self._request_headers(peer)

    async def _on_verack(self, peer: Peer, payload: dict):
        peer.veracked = True
        self._note_sync_progress()

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

    async def _on_headers(self, peer: Peer, payload: dict):
        # request full blocks for unknown headers
        wanted = []
        for hh in (payload.get("headers") or [])[:C.MAX_HEADERS]:
            try:
                hdr_raw = bytes.fromhex(hh)
            except (ValueError, TypeError):
                continue
            try:
                hdr = BlockHeader.deserialize(hdr_raw)
            except ValueError:
                continue
            if self.chain.store is None or \
                    not self.chain.store.block_exists(hdr.hash):
                wanted.append(hdr.hash.hex())
        self._note_sync_progress()
        if wanted:
            await peer.send("getdata", {"blocks": wanted[:C.MAX_INV]})
        else:
            self.synced = True

    async def _on_getdata(self, peer: Peer, payload: dict):
        for h in (payload.get("blocks") or [])[:C.MAX_INV]:
            try:
                bh = bytes.fromhex(h)
            except (ValueError, TypeError):
                continue
            blk = self.chain.get_block(bh)
            if blk is not None:
                await peer.send("block", {"block": blk.serialize().hex()})
        for t in (payload.get("txs") or [])[:C.MAX_INV]:
            try:
                th = bytes.fromhex(t)
            except (ValueError, TypeError):
                continue
            tx = self.mempool.get_tx(th)
            if tx is not None:
                await peer.send("tx", {"tx": tx.serialize().hex()})

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
            await peer.send("getdata", {"blocks": want_blocks,
                                        "txs": want_txs})

    async def _on_block(self, peer: Peer, payload: dict):
        try:
            blk = Block.deserialize(bytes.fromhex(payload["block"]))
        except (ValueError, KeyError, TypeError):
            return
        if blk.header.height > peer.best_height:
            peer.best_height = blk.header.height
        if blk.header.height > self.chain.height() + C.MAX_ORPHAN_BLOCKS:
            # too far ahead: request headers instead of holding garbage
            await self._request_headers(peer)
            return
        await self.submit_block(blk, broadcast=True, exclude=peer)

    async def _on_tx(self, peer: Peer, payload: dict):
        try:
            tx = Transaction.deserialize(bytes.fromhex(payload["tx"]))
        except (ValueError, KeyError, TypeError):
            return
        await self.submit_tx(tx, broadcast=True, exclude=peer)

    async def _on_mempool(self, peer: Peer, payload: dict):
        await peer.send("inv", {"txs": [t.txid().hex()
                                        for t in self.mempool.all_txs()]})

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
        await peer.send("addr", {"addrs": entries[:C.MAX_ADDR_RELAY]})

    async def _on_addr(self, peer: Peer, payload: dict):
        for e in (payload.get("addrs") or [])[:C.MAX_ADDR_RELAY]:
            try:
                host = str(e["host"])
                port = int(e["port"])
            except (KeyError, TypeError, ValueError):
                continue
            if not (1 <= port <= 65535) or not host:
                continue
            self._add_known_addr(host, port)

    # ------------------------------------------------------------------
    # relayed-id caches (bounded)
    # ------------------------------------------------------------------
    def _remember(self, cache: OrderedDict, key: str):
        cache[key] = time.time()
        while len(cache) > self._known_limit:
            cache.popitem(last=False)

    # ------------------------------------------------------------------
    # submission (used by peers, RPC and the miner alike)
    # ------------------------------------------------------------------
    async def submit_block(self, block: Block, broadcast: bool = True,
                           exclude: Optional[Peer] = None) -> bool:
        h = block.hash.hex()
        if h in self._known_blocks:
            return False
        self._remember(self._known_blocks, h)
        if self.chain.store and self.chain.store.block_exists(block.hash):
            return False
        try:
            result = self.chain.connect_block(block)
        except BlockValidationError as e:
            logger.info("rejected block %s: %s", h[:16], e)
            return False
        except Exception as e:  # never let consensus bugs kill a handler
            logger.warning("block connect error %s: %r", h[:16], e)
            return False
        if result.connected:
            logger.info("connected block %d %s", block.height, h[:16])
            self.mempool.on_new_block(block)
            self._note_sync_progress()
            if self.on_block_connected:
                try:
                    self.on_block_connected(block)
                except Exception:
                    pass
            if broadcast:
                await self.broadcast("inv", {"blocks": [h]}, exclude=exclude)
            self.chain.consider_reorg()
            return True
        if result.orphan:
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
            self._remember(self._known_txs, txid)
            if self.on_tx_accepted:
                try:
                    self.on_tx_accepted(tx)
                except Exception:
                    pass
            if broadcast:
                await self.broadcast("inv", {"txs": [txid]}, exclude=exclude)
            return True, "accepted"
        except TxValidationError as e:
            return False, str(e)

    # ------------------------------------------------------------------
    async def broadcast(self, command: str, payload: dict,
                        exclude: Optional[Peer] = None):
        """Relay to all handshaked peers; each peer has its own send queue
        so one slow peer cannot stall the others."""
        for peer in list(self.peers):
            if peer is exclude:
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
        if revived:
            self.mempool.readd_many(revived)
            if self.on_reorg:
                pass
        self.synced = False

    # ------------------------------------------------------------------
    def best_chain_info(self) -> dict:
        return {
            "height": self.chain.height(),
            "best": self.chain.tip_hash().hex(),
            "synced": self.synced,
            "peers": len(self.peers),
        }

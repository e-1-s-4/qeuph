"""
Peer-to-peer node service (asyncio TCP).

Responsibilities:
  * handshake (version/verack) and peer registry
  * headers-first initial block download
  * block/tx relay with inv/getdata
  * feeding validated blocks and transactions into the ChainManager/Mempool

This is the Qeuph port of QRL's twisted-based node (qrl/core/node.py +
qrl/socket/*): same state machine (unsynced -> syncing -> synced), but on
stdlib asyncio.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple

from qeuph import constants as C
from qeuph.config import Network
from qeuph.core.block import Block
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.tx import Transaction
from qeuph.core.validation import BlockValidationError, TxValidationError
from qeuph.network.protocol import COMMANDS, FrameReader, encode_frame

logger = logging.getLogger("qeuph.node")

MAX_HEADERS = 512
MAX_INV = 4096


class Peer:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 node: "QNode"):
        self.reader = reader
        self.writer = writer
        self.node = node
        self.reader_buf = FrameReader(node.network.magic)
        self.peer_version: Optional[dict] = None
        self.veracked = False
        self.best_height = -1
        self.last_seen = time.time()

    @property
    def addr(self) -> str:
        peer = self.writer.get_extra_info("peername")
        return f"{peer[0]}:{peer[1]}" if peer else "?"

    async def send(self, command: str, payload: dict):
        frame = encode_frame(command, payload, self.node.network.magic)
        self.writer.write(frame)
        await self.writer.drain()

    def send_nowait(self, command: str, payload: dict):
        try:
            self.writer.write(encode_frame(command, payload, self.node.network.magic))
        except Exception:
            pass


class QNode:
    """Full node service."""

    def __init__(self, network: Network, chain: ChainManager,
                 mempool: Mempool, connect_peers: Optional[List[Tuple[str, int]]] = None):
        self.network = network
        self.chain = chain
        self.mempool = mempool
        self.peers: List[Peer] = []
        self.connect_peers = connect_peers or []
        self.server: Optional[asyncio.AbstractServer] = None
        self.synced = False
        self._known_txs = set()      # recently relayed txids (hex)
        self._known_blocks = set()   # recently relayed block hashes (hex)
        self._stop = asyncio.Event()
        self.on_block_connected = None   # callback(Block)
        self.on_tx_accepted = None      # callback(Transaction)

    # ------------------------------------------------------------------
    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_connection, "0.0.0.0", self.network.p2p_port)
        logger.info("p2p listening on %d", self.network.p2p_port)
        for host, port in self.connect_peers:
            asyncio.create_task(self._connect_peer(host, port))

    async def stop(self):
        self._stop.set()
        if self.server:
            self.server.close()
        for p in list(self.peers):
            try:
                p.writer.close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # connection handling
    # ------------------------------------------------------------------
    async def _connect_peer(self, host: str, port: int):
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except Exception as e:
            logger.debug("connect %s:%s failed: %s", host, port, e)
            return
        await self._handle_connection(reader, writer)

    async def _handle_connection(self, reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter):
        peer = Peer(reader, writer, self)
        self.peers.append(peer)
        try:
            await self._handshake(peer)
            await self._message_loop(peer)
        except (ConnectionError, asyncio.IncompleteReadError, ValueError) as e:
            logger.debug("peer %s dropped: %s", peer.addr, e)
        finally:
            self.peers.remove(peer)
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

    # ------------------------------------------------------------------
    async def _message_loop(self, peer: Peer):
        while not self._stop.is_set():
            data = await peer.reader.read(65536)
            if not data:
                break
            peer.reader_buf.feed(data)
            while True:
                frame = peer.reader_buf.next_frame()
                if frame is None:
                    break
                command, payload = frame
                peer.last_seen = time.time()
                await self._dispatch(peer, command, payload)

    # ------------------------------------------------------------------
    async def _dispatch(self, peer: Peer, command: str, payload: dict):
        handler = getattr(self, f"_on_{command}", None)
        if handler is None:
            return
        await handler(peer, payload)

    # ------------------------------------------------------------------
    # command handlers
    # ------------------------------------------------------------------
    async def _on_version(self, peer: Peer, payload: dict):
        if payload.get("network") != self.network.name:
            raise ValueError("network mismatch")
        peer.peer_version = payload
        peer.best_height = int(payload.get("height", -1))
        await peer.send("verack", {})
        if peer.best_height > self.chain.height():
            await self._request_headers(peer)

    async def _on_verack(self, peer: Peer, payload: dict):
        peer.veracked = True

    async def _on_ping(self, peer: Peer, payload: dict):
        await peer.send("pong", payload)

    async def _on_pong(self, peer: Peer, payload: dict):
        pass

    async def _request_headers(self, peer: Peer):
        await peer.send("getheaders", {
            "locator": [self.chain.tip_hash().hex()],
            "height": self.chain.height(),
        })

    async def _on_getheaders(self, peer: Peer, payload: dict):
        # serve headers after the highest locator hash we know
        best = -1
        for h in payload.get("locator", []):
            try:
                blk = self.chain.get_block(bytes.fromhex(h))
            except ValueError:
                continue
            if blk is not None:
                best = max(best, blk.height)
        headers = []
        height = best + 1
        while len(headers) < MAX_HEADERS:
            blk = self.chain.get_block_by_height(height)
            if blk is None:
                break
            headers.append(blk.header.serialize().hex())
            height += 1
        await peer.send("headers", {"headers": headers})

    async def _on_headers(self, peer: Peer, payload: dict):
        # request full blocks for unknown headers
        wanted = []
        for hh in payload.get("headers", [])[:MAX_HEADERS]:
            try:
                hdr_raw = bytes.fromhex(hh)
            except ValueError:
                continue
            from qeuph.core.block import BlockHeader
            try:
                hdr = BlockHeader.deserialize(hdr_raw)
            except ValueError:
                continue
            if not self.chain.store or not self.chain.store.block_exists(hdr.hash):
                wanted.append(hdr.hash.hex())
        if wanted:
            await peer.send("getdata", {"blocks": wanted[:MAX_INV]})
        elif not self.synced:
            self.synced = True

    async def _on_getdata(self, peer: Peer, payload: dict):
        for h in payload.get("blocks", [])[:MAX_INV]:
            blk = self.chain.get_block(bytes.fromhex(h))
            if blk is not None:
                await peer.send("block", {"block": blk.serialize().hex()})
        for t in payload.get("txs", [])[:MAX_INV]:
            tx = self.mempool.get_tx(bytes.fromhex(t))
            if tx is not None:
                await peer.send("tx", {"tx": tx.serialize().hex()})

    async def _on_inv(self, peer: Peer, payload: dict):
        blocks = payload.get("blocks", [])[:MAX_INV]
        txs = payload.get("txs", [])[:MAX_INV]
        want_blocks = []
        for h in blocks:
            if h in self._known_blocks:
                continue
            if not self.chain.store or not self.chain.store.block_exists(bytes.fromhex(h)):
                want_blocks.append(h)
        want_txs = [t for t in txs if t not in self._known_txs]
        if want_blocks or want_txs:
            await peer.send("getdata", {"blocks": want_blocks, "txs": want_txs})

    async def _on_block(self, peer: Peer, payload: dict):
        try:
            blk = Block.deserialize(bytes.fromhex(payload["block"]))
        except (ValueError, KeyError):
            return
        await self.submit_block(blk, broadcast=True)

    async def _on_tx(self, peer: Peer, payload: dict):
        try:
            tx = Transaction.deserialize(bytes.fromhex(payload["tx"]))
        except (ValueError, KeyError):
            return
        await self.submit_tx(tx, broadcast=True)

    async def _on_mempool(self, peer: Peer, payload: dict):
        await peer.send("inv", {"txs": [t.txid().hex() for t in self.mempool.all_txs()]})

    # ------------------------------------------------------------------
    # submission (used by peers, RPC and the miner alike)
    # ------------------------------------------------------------------
    async def submit_block(self, block: Block, broadcast: bool = True) -> bool:
        h = block.hash.hex()
        if h in self._known_blocks:
            return False
        self._known_blocks.add(h)
        if self.chain.store and self.chain.store.block_exists(block.hash):
            return False
        try:
            connected = self.chain.connect_block(block)
        except BlockValidationError as e:
            logger.info("rejected block %s: %s", h[:16], e)
            return False
        if connected:
            logger.info("connected block %d %s", block.height, h[:16])
            self.mempool.on_new_block(block)
            self.chain.consider_reorg()
            if self.on_block_connected:
                self.on_block_connected(block)
            if broadcast:
                await self.broadcast("inv", {"blocks": [h]})
            # catch up if we are behind
            if any(p.best_height > self.chain.height() for p in self.peers):
                for p in self.peers:
                    if p.best_height > self.chain.height():
                        await self._request_headers(p)
                        break
            return True
        return False

    async def submit_tx(self, tx: Transaction, broadcast: bool = True) -> Tuple[bool, str]:
        txid = tx.txid().hex()
        if txid in self._known_txs:
            return True, "already known"
        try:
            self.mempool.add_tx(tx)
            self._known_txs.add(txid)
            if self.on_tx_accepted:
                self.on_tx_accepted(tx)
            if broadcast:
                await self.broadcast("inv", {"txs": [txid]})
            return True, "accepted"
        except TxValidationError as e:
            return False, str(e)

    # ------------------------------------------------------------------
    async def broadcast(self, command: str, payload: dict):
        for peer in list(self.peers):
            if peer.veracked or peer.peer_version:
                try:
                    await peer.send(command, payload)
                except Exception:
                    pass

    # ------------------------------------------------------------------
    def best_chain_info(self) -> dict:
        return {
            "height": self.chain.height(),
            "best": self.chain.tip_hash().hex(),
            "synced": self.synced,
            "peers": len(self.peers),
        }

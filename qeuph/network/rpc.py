"""
JSON-RPC 2.0 service over HTTP (stdlib only).

QRL exposed gRPC services (PublicAPIService et al.); Qeuph ships a compact
JSON-RPC surface for the same operations so the full node suite has no
extra mandatory dependencies.

Methods:
    getblockchaininfo                       -> heights, tip, difficulty
    getblockhash {height}                   -> hash
    getblock {hash|height}                  -> full block (hex + parsed)
    gettransaction {txid}                   -> tx + containing block
    getmempoolinfo                          -> size, count
    getmempool                              -> pending txids
    sendtransaction {tx_hex}                -> validate + accept into mempool
    getbalance {address}                    -> confirmed balance (quphi)
    listutxos {address}                     -> confirmed UTXOs
    getnonce {address}                      -> last used txnonce
    getpeerinfo                             -> connected peers
    getrewardinfo {height?}                 -> reward schedule data
    startminer {address} / stopminer        -> solo miner control
    getmininginfo                           -> miner status
    stop                                    -> graceful shutdown
"""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from qeuph.core.block import Block
from qeuph.core.tx import Transaction
from qeuph.core.validation import TxValidationError


class RPCService:
    def __init__(self, node, miner, host: str, port: int, get_stop_event):
        self.node = node
        self.miner = miner
        self.host = host
        self.port = port
        self._stop_event_getter = get_stop_event
        self._server: Optional[ThreadingHTTPServer] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ------------------------------------------------------------------
    def start_background(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        svc = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    req = json.loads(body or b"{}")
                    result = svc.dispatch(req.get("method", ""),
                                           req.get("params", {}) or {})
                    doc = {"jsonrpc": "2.0", "id": req.get("id"), "result": result}
                    code = 200
                except _RpcError as e:
                    doc = {"jsonrpc": "2.0", "id": req.get("id"),
                           "error": {"code": e.code, "message": str(e)}}
                    code = 400
                except Exception as e:
                    doc = {"jsonrpc": "2.0", "id": req.get("id"),
                           "error": {"code": -32603, "message": f"internal: {e}"}}
                    code = 500
                payload = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        t = threading.Thread(target=self._server.serve_forever, daemon=True,
                             name="qeuph-rpc")
        t.start()

    def stop(self):
        if self._server:
            self._server.shutdown()

    # ------------------------------------------------------------------
    def dispatch(self, method: str, params: dict):
        chain = self.node.chain
        state = chain.state
        net = self.node.network
        hrp = net.hrp

        if method == "getblockchaininfo":
            from qeuph.core import pow as pow_mod
            return {
                "chain": net.name,
                "height": chain.height(),
                "best": chain.tip_hash().hex(),
                "difficulty": pow_mod.difficulty_from_bits(chain.tip.header.bits),
                "bits": hex(chain.tip.header.bits),
                "synced": self.node.synced,
                "peers": len(self.node.peers),
                "reward": chain.block_reward(),
            }
        if method == "getblockhash":
            h = int(params.get("height"))
            b = chain.get_block_by_height(h)
            if b is None:
                raise _RpcError(-32001, "block not found")
            return {"hash": b.hash.hex()}
        if method == "getblock":
            arg = params.get("hash") or params.get("height")
            b = None
            if isinstance(arg, int) or (isinstance(arg, str) and arg.isdigit()
                                        and len(arg) < 12):
                b = chain.get_block_by_height(int(arg))
            elif isinstance(arg, str):
                try:
                    b = chain.get_block(bytes.fromhex(arg))
                except ValueError:
                    raise _RpcError(-32002, "bad hash")
            if b is None:
                raise _RpcError(-32001, "block not found")
            verbose = bool(params.get("verbose", True))
            out = {"hash": b.hash.hex(), "hex": b.serialize().hex()}
            if verbose:
                out.update(b.to_dict(hrp))
            return out
        if method == "gettransaction":
            try:
                txid = bytes.fromhex(params["txid"])
            except (KeyError, ValueError):
                raise _RpcError(-32002, "bad txid")
            mp = self.node.mempool.get_tx(txid)
            if mp is not None:
                return {"tx": mp.to_dict(hrp), "mempool": True}
            if chain.store is None:
                raise _RpcError(-32001, "not found")
            loc = chain.store.get_tx_block(txid)
            if loc is None:
                raise _RpcError(-32001, "transaction not found")
            height, bh = loc
            blk = chain.get_block(bh)
            for tx in (blk.transactions if blk else []):
                if tx.txid() == txid:
                    return {"tx": tx.to_dict(hrp), "block": bh.hex(), "height": height}
            raise _RpcError(-32001, "transaction not found")
        if method == "getmempoolinfo":
            return {"count": len(self.node.mempool),
                    "bytes": self.node.mempool.total_size()}
        if method == "getmempool":
            return {"txids": [t.txid().hex() for t in self.node.mempool.all_txs()]}
        if method == "sendtransaction":
            try:
                tx = Transaction.deserialize(bytes.fromhex(params["tx_hex"]))
            except (KeyError, ValueError) as e:
                raise _RpcError(-32002, f"bad transaction: {e}")
            fut = asyncio.run_coroutine_threadsafe(
                self.node.submit_tx(tx, broadcast=True), self._loop)
            accepted, reason = fut.result(timeout=60)
            if not accepted:
                raise _RpcError(-32010, f"rejected: {reason}")
            return {"accepted": True, "txid": tx.txid().hex()}
        if method in ("getbalance", "listutxos", "getnonce"):
            from qeuph.crypto import address as addr_mod
            addr = params.get("address", "")
            ahash = addr_mod.address_to_hash(addr, hrp)
            if ahash is None:
                raise _RpcError(-32002, "invalid address")
            if method == "getbalance":
                return {"address": addr,
                        "balance": state.balance(ahash, chain.height()),
                        "matured_balance": state.balance(ahash, chain.height(),
                                                         matured_only=True)}
            if method == "listutxos":
                rows = state.utxos_for(ahash, chain.height())
                return {"utxos": [{
                    "txid": t.hex(), "index": i, "value": u.value,
                    "is_coinbase": u.is_coinbase,
                    "confirmations": chain.height() - u.cb_height + 1 if u.is_coinbase
                    else chain.height() + 1,
                } for t, i, u in rows]}
            return {"address": addr, "nonce": state.nonce_of(ahash)}
        if method == "getpeerinfo":
            return {"peers": [{
                "addr": p.addr,
                "version": p.peer_version.get("version") if p.peer_version else None,
                "best_height": p.best_height,
                "last_seen": p.last_seen,
            } for p in self.node.peers]}
        if method == "getrewardinfo":
            from qeuph.core import reward as reward_mod
            height = int(params.get("height", chain.height()))
            return {
                "height": height,
                "epoch": reward_mod.epoch_at(height),
                "reward": reward_mod.block_reward(height),
                "next_epoch_height": (reward_mod.epoch_at(height) + 1)
                                      * __import__("qeuph.constants", fromlist=["x"]).REWARD_INTERVAL,
            }
        if method == "startminer":
            if self.miner is None:
                raise _RpcError(-32020, "miner not available")
            addr = params.get("address", "")
            from qeuph.crypto import address as addr_mod
            ahash = addr_mod.address_to_hash(addr, hrp)
            if ahash is None:
                raise _RpcError(-32002, "invalid payout address")
            self.miner.set_payout(ahash)
            self.miner.start()
            return {"mining": True, "address": addr}
        if method == "stopminer":
            if self.miner is not None:
                self.miner.stop()
            return {"mining": False}
        if method == "getmininginfo":
            if self.miner is None:
                return {"mining": False}
            return {"mining": self.miner.is_mining(),
                    "hashrate": self.miner.hashrate(),
                    "blocks_mined": self.miner.blocks_mined,
                    "payout": self.miner.payout_address_hex}
        if method == "stop":

            async def _do_stop():
                self._stop_event_getter().set()

            asyncio.run_coroutine_threadsafe(_do_stop(), self._loop)
            return {"stopping": True}
        raise _RpcError(-32601, f"unknown method {method!r}")


class _RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code

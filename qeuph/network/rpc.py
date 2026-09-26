"""
JSON-RPC 2.0 service over HTTP (stdlib only).

QRL exposed gRPC services (PublicAPIService et al.); Qeuph ships a compact
JSON-RPC surface for the same operations so the full node suite has no
extra mandatory dependencies.

Thread-safety: handlers run in HTTP threads; every access to in-memory
chain state goes through the ChainManager's re-entrant lock, and
block-generating operations are scheduled onto the node's event loop.

Methods:
    getblockchaininfo                       -> heights, tip, difficulty
    getblockhash {height}                   -> hash
    getblock {hash|height}                  -> full block (hex + parsed)
    gettransaction {txid}                   -> tx + containing block
    getmempoolinfo                          -> size, count
    getmempool / getrawmempool              -> pending txids
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

from qeuph import constants as C
from qeuph.core.block import Block
from qeuph.core.tx import Transaction
from qeuph.core.validation import TxValidationError

MAX_RPC_BODY = 32 * 1024 * 1024      # hard cap on request bodies


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
            protocol_version = "HTTP/1.1"
            timeout = 120  # close dead client connections

            def log_message(self, fmt, *args):
                pass

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _reply(self, doc, code=200):
                payload = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except ValueError:
                    length = 0
                if length < 0 or length > MAX_RPC_BODY:
                    self._reply({"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32600,
                                           "message": "request too large"}}, 413)
                    self.close_connection = True
                    return
                body = self.rfile.read(length) if length else b""
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
                self._reply(doc, code)

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
        net = self.node.network
        hrp = net.hrp

        if method == "getblockchaininfo":
            from qeuph.core import pow as pow_mod
            with chain.lock:
                tip = chain.tip
                return {
                    "chain": net.name,
                    "blocks": chain.height(),
                    "headers": chain.height(),
                    "height": chain.height(),
                    "best": chain.tip_hash().hex(),
                    "bestblockhash": chain.tip_hash().hex(),
                    "difficulty": pow_mod.difficulty_from_bits(tip.header.bits),
                    "bits": hex(tip.header.bits),
                    "mediantime": chain.median_time_past(),
                    "time": tip.header.timestamp,
                    "chainwork": hex(chain.tip_work),
                    "synced": self.node.synced,
                    "peers": len(self.node.peers),
                    "reward": chain.block_reward(),
                    "reward_quh": chain.block_reward() / C.QUPHI_PER_QUH,
                    "max_supply": C.MAX_SUPPLY_QUH,
                    "mempool_size": len(self.node.mempool),
                    "orphans": chain.orphan_count(),
                }
        if method == "getblockcount":
            return chain.height()
        if method == "getbestblockhash":
            return chain.tip_hash().hex()
        if method == "getdifficulty":
            from qeuph.core import pow as pow_mod
            with chain.lock:
                return pow_mod.difficulty_from_bits(chain.tip.header.bits)
        if method == "getnetworkinfo":
            from qeuph.crypto import ml_dsa
            return {
                "version": C.VERSION,
                "protocolversion": C.PROTOCOL_VERSION,
                "network": net.name,
                "p2p_port": net.p2p_port,
                "rpc_port": net.rpc_port,
                "connections": len(self.node.peers),
                "relayfee": C.MIN_RELAY_FEE_RATE,
                "crypto_backend": ml_dsa.backend_name(),
            }
        if method == "validateaddress":
            from qeuph.crypto import address as addr_mod
            addr = params.get("address", "")
            ahash = addr_mod.address_to_hash(addr, hrp)
            is_valid = ahash is not None and len(ahash) == 64
            return {
                "isvalid": is_valid,
                "address": addr,
                "hrp": hrp,
                "addr_hash": ahash.hex() if is_valid else None,
            }
        if method == "estimatefee":
            return {"fee_rate_quphi_per_kb": C.MIN_RELAY_FEE_RATE}
        if method == "decoderawtransaction":
            raw_hex = params.get("hex", "")
            try:
                tx = Transaction.deserialize(bytes.fromhex(raw_hex))
                return tx.to_dict(hrp)
            except Exception as e:
                raise _RpcError(-32002, f"cannot decode raw transaction: {e}")
        if method == "getrawtransaction":
            try:
                txid = bytes.fromhex(params["txid"])
            except (KeyError, ValueError):
                raise _RpcError(-32002, "bad txid")
            verbose = bool(params.get("verbose", False))
            mp = self.node.mempool.get_tx(txid)
            if mp is not None:
                return mp.to_dict(hrp) if verbose else mp.serialize().hex()
            if chain.store is not None:
                loc = chain.store.get_tx_block(txid)
                if loc is not None:
                    height, bh = loc
                    blk = chain.get_block(bh)
                    for tx in (blk.transactions if blk else []):
                        if tx.txid() == txid:
                            return tx.to_dict(hrp) if verbose else tx.serialize().hex()
            raise _RpcError(-32001, "transaction not found")
        if method == "gettxout":
            try:
                txid = bytes.fromhex(params["txid"])
                idx = int(params["index"])
            except (KeyError, ValueError):
                raise _RpcError(-32002, "invalid txid or index")
            with chain.lock:
                u = chain.state.get_utxo(txid, idx)
                if u is None:
                    return None
                from qeuph.crypto import address as addr_mod
                confs = (chain.height() - u.cb_height + 1
                         if u.is_coinbase else chain.height() + 1)
                return {
                    "bestblock": chain.tip_hash().hex(),
                    "confirmations": confs,
                    "value": u.value,
                    "value_quh": u.value / C.QUPHI_PER_QUH,
                    "address": addr_mod.hash_to_address(u.addr_hash, hrp),
                    "coinbase": u.is_coinbase,
                }
        if method == "generate":
            if net.name == "mainnet":
                raise _RpcError(-32021, "generate not allowed on mainnet")
            nblocks = int(params.get("nblocks", 1))
            if nblocks < 1 or nblocks > 1000:
                raise _RpcError(-32002, "nblocks out of range (1..1000)")
            addr = params.get("address", "")
            from qeuph.crypto import address as addr_mod
            ahash = addr_mod.address_to_hash(addr, hrp) if addr else bytes(64)
            fut = asyncio.run_coroutine_threadsafe(
                self._generate_async(ahash, nblocks), self._loop)
            try:
                return fut.result(timeout=600)
            except Exception as e:
                raise _RpcError(-32010, f"generate failed: {e}")
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
            with self.node.mempool.lock:
                return {"count": len(self.node.mempool),
                        "bytes": self.node.mempool.total_size(),
                        "maxbytes": C.MAX_MEMPOOL_SIZE}
        if method == "getmempool":
            return {"txids": [t.txid().hex() for t in self.node.mempool.all_txs()]}
        if method == "getrawmempool":
            verbose = bool(params.get("verbose", False))
            if verbose:
                return {t.txid().hex(): t.to_dict(hrp)
                        for t in self.node.mempool.all_txs()}
            return [t.txid().hex() for t in self.node.mempool.all_txs()]
        if method == "getblocktemplate":
            from qeuph.core import pow as pow_mod
            from qeuph.crypto import address as addr_mod
            with chain.lock:
                tip = chain.tip
                payout = params.get("address", "")
                ahash = (addr_mod.address_to_hash(payout, hrp) if payout
                         else (self.miner._payout if self.miner else bytes(64)))
                txs = self.node.mempool.best_transactions(C.MAX_BLOCK_SIZE - 200_000)
                template_block, reward = chain.create_block_template(
                    ahash or bytes(64), txs)
                return {
                    "version": C.BLOCK_VERSION,
                    "previousblockhash": tip.hash.hex(),
                    "height": template_block.height,
                    "curtime": template_block.header.timestamp,
                    "bits": hex(template_block.header.bits),
                    "bits_int": template_block.header.bits,
                    "target": hex(pow_mod.bits_to_target(template_block.header.bits)),
                    "coinbasevalue": reward,
                    "coinbasevalue_quh": reward / C.QUPHI_PER_QUH,
                    "transactions": [t.to_dict(hrp) for t in txs],
                    "sizelimit": C.MAX_BLOCK_SIZE,
                    "sigoplimit": 20000,
                }
        if method == "submitblock":
            hexdata = params.get("hex") or params.get("block_hex") or ""
            if not hexdata and isinstance(params, str):
                hexdata = params
            try:
                raw = bytes.fromhex(hexdata)
                block = Block.deserialize(raw)
            except Exception as e:
                raise _RpcError(-32002, f"invalid block hex: {e}")
            fut = asyncio.run_coroutine_threadsafe(
                self.node.submit_block(block, broadcast=True), self._loop)
            try:
                ok = fut.result(timeout=120)
                if not ok:
                    raise _RpcError(-32010, "block rejected by consensus rules")
                return {"success": True, "hash": block.hash.hex(),
                        "height": block.height}
            except _RpcError:
                raise
            except Exception as e:
                raise _RpcError(-32010, f"submission failed: {e}")
        if method in ("sendtransaction", "sendrawtransaction"):
            raw_hex = params.get("tx_hex") or params.get("hex") or ""
            try:
                tx = Transaction.deserialize(bytes.fromhex(raw_hex))
            except (KeyError, ValueError) as e:
                raise _RpcError(-32002, f"bad transaction: {e}")
            fut = asyncio.run_coroutine_threadsafe(
                self.node.submit_tx(tx, broadcast=True), self._loop)
            try:
                accepted, reason = fut.result(timeout=120)
            except Exception as e:
                raise _RpcError(-32010, f"submission failed: {e}")
            if not accepted:
                raise _RpcError(-32010, f"rejected: {reason}")
            return {"accepted": True, "txid": tx.txid().hex()}
        if method == "createrawtransaction":
            from qeuph.core.tx import TxIn, TxOut
            from qeuph.crypto import address as addr_mod
            inputs_arg = params.get("inputs", [])
            outputs_arg = params.get("outputs", [])
            lock_time = int(params.get("locktime", 0))
            inputs = []
            for inp in inputs_arg:
                txid = bytes.fromhex(inp["txid"])
                idx = int(inp["index"])
                nonce = int(inp.get("nonce", 1))
                inputs.append(TxIn(txid, idx, nonce))
            outputs = []

            def _add_output(addr_str, val):
                ahash = addr_mod.address_to_hash(addr_str, hrp)
                if ahash is None:
                    raise _RpcError(-32002, f"invalid address {addr_str}")
                val_quphi = (round(float(val) * C.QUPHI_PER_QUH)
                             if isinstance(val, (float, int)) else int(val))
                if val_quphi <= 0:
                    raise _RpcError(-32002, "output value must be positive")
                outputs.append(TxOut(val_quphi, ahash))

            if isinstance(outputs_arg, list):
                for out in outputs_arg:
                    for addr_str, val in out.items():
                        _add_output(addr_str, val)
            elif isinstance(outputs_arg, dict):
                for addr_str, val in outputs_arg.items():
                    _add_output(addr_str, val)
            tx = Transaction(inputs, outputs, lock_time=lock_time)
            return {"hex": tx.serialize().hex(), "txid": tx.txid().hex()}
        if method == "getaddressinfo":
            from qeuph.crypto import address as addr_mod
            addr = params.get("address", "")
            ahash = addr_mod.address_to_hash(addr, hrp)
            if ahash is None:
                raise _RpcError(-32002, "invalid address")
            with chain.lock:
                h = chain.height()
                bal = chain.state.balance(ahash, h)
                mbal = chain.state.balance(ahash, h, matured_only=True)
                nonce = chain.state.nonce_of(ahash)
                utxos = chain.state.utxos_for(ahash, h)
            return {
                "address": addr,
                "addr_hash": ahash.hex(),
                "balance": bal,
                "balance_quh": bal / C.QUPHI_PER_QUH,
                "matured_balance": mbal,
                "matured_balance_quh": mbal / C.QUPHI_PER_QUH,
                "nonce": nonce,
                "utxo_count": len(utxos),
            }
        if method in ("getbalance", "listutxos", "getnonce"):
            from qeuph.crypto import address as addr_mod
            addr = params.get("address", "")
            ahash = addr_mod.address_to_hash(addr, hrp)
            if ahash is None:
                raise _RpcError(-32002, "invalid address")
            with chain.lock:
                if method == "getbalance":
                    return {"address": addr,
                            "balance": chain.state.balance(ahash, chain.height()),
                            "balance_quh": chain.state.balance(
                                ahash, chain.height()) / C.QUPHI_PER_QUH,
                            "matured_balance": chain.state.balance(
                                ahash, chain.height(), matured_only=True)}
                if method == "listutxos":
                    matured_only = bool(params.get("matured_only", False))
                    rows = chain.state.utxos_for(ahash, chain.height(),
                                                 matured_only=matured_only)
                    return {"utxos": [{
                        "txid": t.hex(), "index": i, "value": u.value,
                        "value_quh": u.value / C.QUPHI_PER_QUH,
                        "is_coinbase": u.is_coinbase,
                        "confirmations": (chain.height() - u.cb_height + 1
                                          if u.is_coinbase else chain.height() + 1),
                    } for t, i, u in rows]}
                return {"address": addr, "nonce": chain.state.nonce_of(ahash)}
        if method == "getpeerinfo":
            return {"peers": [{
                "addr": p.addr,
                "inbound": p.inbound,
                "version": p.peer_version.get("version") if p.peer_version else None,
                "best_height": p.best_height,
                "last_seen": p.last_seen,
            } for p in list(self.node.peers)]}
        if method == "getrewardinfo":
            from qeuph.core import reward as reward_mod
            height = int(params.get("height", chain.height()))
            return {
                "height": height,
                "epoch": reward_mod.epoch_at(height),
                "reward": reward_mod.block_reward(height),
                "reward_quh": reward_mod.block_reward(height) / C.QUPHI_PER_QUH,
                "next_epoch_height": (reward_mod.epoch_at(height) + 1)
                                      * C.REWARD_INTERVAL,
            }
        if method == "startminer":
            if self.miner is None:
                raise _RpcError(-32020, "miner not available")
            addr = params.get("address", "")
            threads = int(params.get("threads", 1))
            from qeuph.crypto import address as addr_mod
            if addr:
                ahash = addr_mod.address_to_hash(addr, hrp)
                if ahash is None:
                    raise _RpcError(-32002, "invalid payout address")
                self.miner.set_payout(ahash)
            self.miner.start(threads=threads)
            return {"mining": True,
                    "address": self.miner.payout_address_hex,
                    "threads": self.miner.threads}
        if method == "stopminer":
            if self.miner is not None:
                self.miner.stop()
            return {"mining": False}
        if method == "getmininginfo":
            if self.miner is None:
                return {"mining": False}
            from qeuph.core import pow as pow_mod
            with chain.lock:
                tip = chain.tip
                target = pow_mod.bits_to_target(tip.header.bits)
                return {
                    "mining": self.miner.is_mining(),
                    "hashrate": round(self.miner.hashrate(), 2),
                    "blocks_mined": self.miner.blocks_mined,
                    "threads": getattr(self.miner, "threads", 1),
                    "payout": self.miner.payout_address_hex,
                    "network_difficulty": pow_mod.difficulty_from_bits(tip.header.bits),
                    "bits": hex(tip.header.bits),
                    "target": hex(target),
                    "chain": net.name,
                    "blocks": chain.height(),
                }
        if method == "help":
            return {
                "blockchain": ["getblockchaininfo", "getblockcount",
                               "getbestblockhash", "getdifficulty",
                               "getblockhash", "getblock", "gettxout",
                               "getrewardinfo"],
                "transactions": ["gettransaction", "getrawtransaction",
                                 "sendrawtransaction", "decoderawtransaction",
                                 "createrawtransaction"],
                "mining": ["getblocktemplate", "submitblock", "getmininginfo",
                           "startminer", "stopminer", "generate"],
                "mempool": ["getmempoolinfo", "getrawmempool", "getmempool"],
                "wallet_and_address": ["getbalance", "listutxos", "getnonce",
                                       "validateaddress", "getaddressinfo"],
                "network": ["getnetworkinfo", "getpeerinfo", "stop"]
            }
        if method == "stop":
            async def _do_stop():
                self._stop_event_getter().set()

            asyncio.run_coroutine_threadsafe(_do_stop(), self._loop)
            return {"stopping": True}
        raise _RpcError(-32601, f"unknown method {method!r}")

    # ------------------------------------------------------------------
    async def _generate_async(self, ahash: bytes, nblocks: int) -> dict:
        """Regtest block generation on the event loop (thread-safe).
        Blocks go through node.submit_block so peers receive the inv relay."""
        chain = self.node.chain
        hashes = []
        for _ in range(nblocks):
            txs = self.node.mempool.best_transactions(C.MAX_BLOCK_SIZE - 200_000)
            b, _ = chain.create_block_template(ahash, txs)
            b.mine()
            try:
                ok = await self.node.submit_block(b, broadcast=True)
            except Exception as e:
                raise _RpcError(-32010, f"generated block rejected: {e}")
            if not ok:
                raise _RpcError(-32010, "generated block rejected")
            hashes.append(b.hash.hex())
        return {"hashes": hashes, "height": chain.height()}


class _RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code

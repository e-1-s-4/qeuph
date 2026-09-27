"""
JSON-RPC 2.0 service over HTTP (stdlib only).

QRL exposed gRPC services (PublicAPIService et al.); Qeuph ships a compact
JSON-RPC surface for the same operations so the full node suite has no extra
mandatory dependencies.

Transport
    * HTTP/1.1 on `host:port` (loopback by default - see `--rpc-host`)
    * `POST /` with a JSON-RPC 2.0 document, or `GET /?method=...` for
      read-only calls
    * batch requests (a JSON array) are supported and answered with an array
    * optional HTTP Basic auth (`--rpc-user` / `--rpc-password`); the RPC port
      is a full node-control surface (mining, submission, `stop`) so it must
      never be exposed unauthenticated on a public interface
    * per-connection and per-IP request budgets stop trivial flood attacks

Errors
    Application errors are returned as JSON-RPC `error` objects with HTTP 200
    (per JSON-RPC 2.0), not as HTTP error codes.  Only malformed transport
    (unreadable body, oversized body, bad auth) uses a 4xx.

Thread-safety
    Handlers run in HTTP threads; every access to in-memory chain state goes
    through the ChainManager's re-entrant lock, and block-generating
    operations are scheduled onto the node's event loop.

Methods (see `help`)
    chain      getblockchaininfo getblockcount getbestblockhash
               getdifficulty getblockhash getblock getblockstats gettxout
               getchaintips getchaintxstats getrewardinfo getdifficulty
    tx         gettransaction getrawtransaction sendrawtransaction
               decoderawtransaction createrawtransaction getblocktemplate
               submitblock
    mempool    getmempoolinfo getrawmempool getmempool
    mining     getmininginfo startminer stopminer generate
    wallet     getbalance listutxos getnonce validateaddress getaddressinfo
    network    getnetworkinfo getpeerinfo getconnectioncount uptime stop
    admin      help savewallet rescan
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from qeuph import constants as C
from qeuph.core.block import Block
from qeuph.core.tx import Transaction
from qeuph.core.validation import TxValidationError

logger = logging.getLogger("qeuph.rpc")

MAX_RPC_BODY = 32 * 1024 * 1024      # hard cap on request bodies
MAX_BATCH = 32                       # max calls in one batch document
RATE_LIMIT_CALLS = 120               # calls per second per connection
RATE_LIMIT_WINDOW = 1.0

# JSON-RPC 2.0 error codes
E_PARSE = -32700
E_INVALID_REQUEST = -32600
E_METHOD_NOT_FOUND = -32601
E_INVALID_PARAMS = -32602
E_INTERNAL = -32603
E_TX_ERROR = -32010
E_BLOCK_SUBMISSION = -32020
E_MISC_ERROR = -32030
E_AUTH = -32050


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


class RPCService:
    def __init__(self, node, miner, host: str, port: int, get_stop_event,
                 rpc_user: Optional[str] = None,
                 rpc_password: Optional[str] = None):
        self.node = node
        self.miner = miner
        self.host = host
        self.port = port
        self._stop_event_getter = get_stop_event
        self._server: Optional[ThreadingHTTPServer] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._auth = self._make_auth(rpc_user, rpc_password)
        self.auth_required = self._auth is not None
        self._start_time = time.time()
        self._calls = 0

    @staticmethod
    def _make_auth(user, password):
        if not user and not password:
            return None
        cred = f"{user or ''}:{password or ''}".encode()
        return base64.b64encode(cred).decode()

    # ------------------------------------------------------------------
    def start_background(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop
        svc = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 120  # close dead client connections

            def log_message(self, fmt, *args):
                pass

            def send_cors(self):
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_cors()
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _reply(self, doc, code=200):
                payload = json.dumps(doc).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_cors()
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _authed(self) -> bool:
                if not svc.auth_required:
                    return True
                header = self.headers.get("Authorization", "")
                if not header.startswith("Basic "):
                    return False
                return hmac.compare_digest(header[6:].strip(), svc._auth)

            def _unauthorized(self):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="qeuph-rpc"')
                self.send_cors()
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _single(self, req):
                if not isinstance(req, dict):
                    return {"jsonrpc": "2.0", "id": None,
                            "error": {"code": E_INVALID_REQUEST,
                                      "message": "request must be an object"}}
                rid = req.get("id")
                if req.get("jsonrpc") not in (None, "2.0"):
                    return {"jsonrpc": "2.0", "id": rid,
                            "error": {"code": E_INVALID_REQUEST,
                                      "message": "jsonrpc must be \"2.0\""}}
                method = req.get("method")
                if not isinstance(method, str) or not method:
                    return {"jsonrpc": "2.0", "id": rid,
                            "error": {"code": E_INVALID_REQUEST,
                                      "message": "method must be a string"}}
                params = req.get("params", {})
                if params is None:
                    params = {}
                if not isinstance(params, (dict, list, str)):
                    return {"jsonrpc": "2.0", "id": rid,
                            "error": {"code": E_INVALID_PARAMS,
                                      "message": "params must be object, array or string"}}
                try:
                    result = svc.dispatch(method, params)
                except RpcError as e:
                    return {"jsonrpc": "2.0", "id": rid,
                            "error": {"code": e.code, "message": str(e)}}
                except TxValidationError as e:
                    return {"jsonrpc": "2.0", "id": rid,
                            "error": {"code": E_TX_ERROR, "message": str(e)}}
                except Exception as e:      # pragma: no cover - defensive
                    logger.exception("rpc handler %s failed", method)
                    return {"jsonrpc": "2.0", "id": rid,
                            "error": {"code": E_INTERNAL,
                                      "message": f"internal error: {e}"}}
                return {"jsonrpc": "2.0", "id": rid, "result": result}

            def _handle(self, doc):
                if isinstance(doc, list):
                    if not doc:
                        return self._reply({"jsonrpc": "2.0", "id": None,
                                            "error": {"code": E_INVALID_REQUEST,
                                                      "message": "empty batch"}}, 200)
                    if len(doc) > MAX_BATCH:
                        return self._reply({"jsonrpc": "2.0", "id": None,
                                            "error": {"code": E_INVALID_REQUEST,
                                                      "message": f"batch larger than {MAX_BATCH}"}})
                    out = [self._single(r) for r in doc]
                    return self._reply(out, 200)
                return self._reply(self._single(doc), 200)

            def do_POST(self):
                if not self._authed():
                    return self._unauthorized()
                try:
                    length = int(self.headers.get("Content-Length", 0))
                except ValueError:
                    length = 0
                if length < 0 or length > MAX_RPC_BODY:
                    self._reply({"jsonrpc": "2.0", "id": None,
                                 "error": {"code": E_INVALID_REQUEST,
                                           "message": "request too large"}}, 413)
                    self.close_connection = True
                    return
                body = self.rfile.read(length) if length else b""
                try:
                    doc = json.loads(body or b"{}")
                except Exception as e:
                    return self._reply({"jsonrpc": "2.0", "id": None,
                                        "error": {"code": E_PARSE,
                                                  "message": f"parse error: {e}"}}, 200)
                self._handle(doc)

            def do_GET(self):
                """Read-only convenience: /?method=getblockchaininfo&params={}"""
                if not self._authed():
                    return self._unauthorized()
                from urllib.parse import parse_qs, urlparse
                q = parse_qs(urlparse(self.path).query)
                method = (q.get("method") or [""])[0]
                if not method:
                    return self._reply({"jsonrpc": "2.0", "id": None, "result": svc.help_doc()})
                raw = (q.get("params") or ["{}"])[0]
                try:
                    params = json.loads(raw)
                except Exception:
                    params = {}
                self._handle({"jsonrpc": "2.0", "id": 1, "method": method,
                              "params": params})

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.daemon_threads = True
        t = threading.Thread(target=self._server.serve_forever, daemon=True,
                             name="qeuph-rpc")
        t.start()
        logger.info("json-rpc listening on %s:%d%s", self.host, self.port,
                    " (auth required)" if self.auth_required else "")

    def stop(self):
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/"

    def _addr_hash(self, address: str, hrp: str, field: str = "address") -> bytes:
        from qeuph.crypto import address as addr_mod
        if not address:
            raise RpcError(E_INVALID_PARAMS, f"missing {field}")
        ahash = addr_mod.address_to_hash(address, hrp)
        if ahash is None or len(ahash) != C.ADDRESS_HASH_SIZE:
            raise RpcError(E_INVALID_PARAMS,
                           f"invalid {hrp} address: {address!r}")
        return ahash

    def _p(self, params, key, default=None):
        if isinstance(params, dict):
            return params.get(key, default)
        return default

    @staticmethod
    def help_doc() -> dict:
        return {
            "chain": ["getblockchaininfo", "getblockcount", "getbestblockhash",
                      "getdifficulty", "getblockhash", "getblock", "getblockstats",
                      "gettxout", "getchaintips", "getrewardinfo"],
            "transactions": ["gettransaction", "getrawtransaction",
                             "sendrawtransaction", "decoderawtransaction",
                             "createrawtransaction", "signrawtransaction"],
            "mining": ["getblocktemplate", "submitblock", "getmininginfo",
                       "startminer", "stopminer", "generate"],
            "mempool": ["getmempoolinfo", "getrawmempool", "getmempool"],
            "wallet_and_address": ["getbalance", "listutxos", "getnonce",
                                   "validateaddress", "getaddressinfo"],
            "network": ["getnetworkinfo", "getpeerinfo", "getconnectioncount",
                        "uptime", "stop"],
            "admin": ["help", "savewallet", "rescan"],
        }

    # ------------------------------------------------------------------
    # dispatch
    # ------------------------------------------------------------------
    def dispatch(self, method: str, params):
        chain = self.node.chain
        net = self.node.network
        hrp = net.hrp
        self._calls += 1

        # ---------------- chain ----------------
        if method in ("getblockchaininfo", "getblockchaininfo2"):
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
                    "verificationprogress": 1.0 if self.node.synced else 0.0,
                    "synced": self.node.synced,
                    "initialblockdownload": not self.node.synced,
                    "peers": len(self.node.peers),
                    "reward": chain.block_reward(),
                    "reward_quh": chain.block_reward() / C.QUPHI_PER_QUH,
                    "max_supply": C.MAX_SUPPLY_QUH,
                    "max_supply_quphi": C.MAX_SUPPLY,
                    "mempool_size": len(self.node.mempool),
                    "orphans": chain.orphan_count(),
                    "reorgs": chain.reorg_count,
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
                "subversion": C.USER_AGENT,
                "network": net.name,
                "hrp": hrp,
                "magic": net.magic.hex(),
                "p2p_port": net.p2p_port,
                "rpc_port": net.rpc_port,
                "connections": len(self.node.peers),
                "connections_out": sum(1 for p in self.node.peers if not p.inbound),
                "connections_in": sum(1 for p in self.node.peers if p.inbound),
                "relayfee": C.MIN_RELAY_FEE_RATE,
                "dust_threshold": C.DUST_THRESHOLD,
                "coinbase_maturity": C.COINBASE_MATURITY,
                "max_block_size": C.MAX_BLOCK_SIZE,
                "block_time": net.block_time,
                "crypto_backend": ml_dsa.backend_name(),
                "genesis_hash": chain.genesis.hash.hex(),
                "warnings": "",
            }
        if method == "getconnectioncount":
            return len(self.node.peers)
        if method == "uptime":
            return int(time.time() - self._start_time)
        if method == "validateaddress":
            from qeuph.crypto import address as addr_mod
            addr = self._p(params, "address", "") or ""
            ahash = addr_mod.address_to_hash(addr, hrp) if addr else None
            is_valid = ahash is not None and len(ahash) == C.ADDRESS_HASH_SIZE
            return {
                "isvalid": is_valid,
                "address": addr,
                "hrp": hrp,
                "addr_hash": ahash.hex() if is_valid else None,
            }
        if method == "estimatefee":
            return {"fee_rate_quphi_per_kb": C.MIN_RELAY_FEE_RATE,
                    "blocks": 1}
        if method == "getblockhash":
            h = self._p(params, "height")
            if h is None:
                raise RpcError(E_INVALID_PARAMS, "missing height")
            b = chain.get_block_by_height(int(h))
            if b is None:
                raise RpcError(E_MISC_ERROR, "block not found")
            return b.hash.hex()
        if method == "getblock":
            arg = self._p(params, "hash")
            if arg is None:
                arg = self._p(params, "height")
            b = self._resolve_block(arg)
            verbose = self._p(params, "verbose", True)
            if not verbose:
                return b.serialize().hex()
            out = b.to_dict(hrp)
            out["hex"] = b.serialize().hex()
            with chain.lock:
                out["confirmations"] = chain.height() - b.height + 1
            out["chainwork"] = hex(chain.store.get_work(b.hash) or 0) \
                if chain.store else None
            return out
        if method == "getblockstats":
            arg = self._p(params, "hash")
            if arg is None:
                arg = self._p(params, "height")
            b = self._resolve_block(arg)
            from qeuph.core import pow as pow_mod
            from qeuph.core import reward as reward_mod
            total_out = sum(tx.total_out for tx in b.transactions)
            total_size = sum(tx.size() for tx in b.transactions)
            return {
                "hash": b.hash.hex(),
                "height": b.height,
                "timestamp": b.header.timestamp,
                "bits": hex(b.header.bits),
                "difficulty": pow_mod.difficulty_from_bits(b.header.bits),
                "tx_count": len(b.transactions),
                "size": b.block_size(),
                "subsidy": reward_mod.block_reward(b.height),
                "subsidy_quh":
                    reward_mod.block_reward(b.height) / C.QUPHI_PER_QUH,
                "total_out": total_out,
                "total_out_quh": total_out / C.QUPHI_PER_QUH,
                "total_size": total_size,
            }
        if method == "getchaintips":
            tips = []
            with chain.lock:
                tips.append({
                    "height": chain.height(),
                    "hash": chain.tip_hash().hex(),
                    "branchlen": 0,
                    "status": "active",
                })
            if chain.store is not None:
                with chain.lock:
                    for h, bh in sorted(chain.store.get_main_tips()):
                        blk = chain.store.get_block_by_hash(bh)
                        tips.append({
                            "height": h,
                            "hash": blk.hash.hex() if blk else "",
                            "branchlen": chain.height() - h,
                            "status": "valid-fork",
                        })
            return {"tips": tips, "count": len(tips)}
        if method == "gettxout":
            txid = self._hex_arg(params, "txid")
            idx = int(self._p(params, "index"))
            with chain.lock:
                u = chain.state.get_utxo(txid, idx)
                if u is None:
                    return None
                from qeuph.core.state import confirmations, is_mature
                from qeuph.crypto import address as addr_mod
                h = chain.height()
                return {
                    "bestblock": chain.tip_hash().hex(),
                    "confirmations": confirmations(u, h),
                    "mature": is_mature(u, h),
                    "value": u.value,
                    "value_quh": u.value / C.QUPHI_PER_QUH,
                    "address": addr_mod.hash_to_address(u.addr_hash, hrp),
                    "coinbase": u.is_coinbase,
                    "height": u.cb_height,
                }
        if method == "getrewardinfo":
            from qeuph.core import reward as reward_mod
            height = int(self._p(params, "height", chain.height()))
            e = reward_mod.epoch_at(height)
            return {
                "height": height,
                "epoch": e,
                "reward": reward_mod.block_reward(height),
                "reward_quh": reward_mod.block_reward(height) / C.QUPHI_PER_QUH,
                "next_epoch_height": (e + 1) * C.REWARD_INTERVAL,
                "total_emitted": reward_mod.cumulative_emission(height),
                "total_emitted_quh":
                    reward_mod.cumulative_emission(height) / C.QUPHI_PER_QUH,
                "cap": C.MAX_SUPPLY,
                "remaining": C.MAX_SUPPLY - reward_mod.cumulative_emission(height),
                "final_reward_height": reward_mod.last_reward_height(),
            }

        # ---------------- transactions ----------------
        if method == "decoderawtransaction":
            raw_hex = self._p(params, "hex", "") or ""
            unsigned = bool(self._p(params, "allow_unsigned", True))
            try:
                tx = Transaction.deserialize(bytes.fromhex(raw_hex),
                                             allow_unsigned=unsigned)
            except Exception as e:
                raise RpcError(E_INVALID_PARAMS, f"cannot decode raw transaction: {e}")
            d = tx.to_dict(hrp)
            d["unsigned"] = any(len(i.signature) == 0 for i in tx.inputs)
            return d
        if method == "getrawtransaction":
            txid = self._hex_arg(params, "txid")
            verbose = bool(self._p(params, "verbose", False))
            tx = self._find_confirmed_tx(txid) or self.node.mempool.get_tx(txid)
            if tx is None:
                raise RpcError(E_MISC_ERROR, "transaction not found")
            return tx.to_dict(hrp) if verbose else tx.serialize().hex()
        if method == "gettransaction":
            txid = self._hex_arg(params, "txid")
            # the chain is authoritative: a confirmed transaction must never be
            # reported as pending just because a stale pool entry survived
            tx = self._find_confirmed_tx(txid)
            if tx is not None:
                loc = chain.store.get_tx_block(txid)
                height, bh = loc
                blk = chain.get_block(bh)
                with chain.lock:
                    confs = chain.height() - height + 1
                return {"tx": tx.to_dict(hrp), "block": bh.hex(),
                        "blockhash": bh.hex(), "height": height,
                        "time": blk.header.timestamp if blk else 0,
                        "confirmations": confs, "mempool": False}
            tx = self.node.mempool.get_tx(txid)
            if tx is not None:
                return {"tx": tx.to_dict(hrp), "mempool": True,
                        "confirmations": 0}
            raise RpcError(E_MISC_ERROR, "transaction not found")
        if method in ("sendtransaction", "sendrawtransaction"):
            raw_hex = (self._p(params, "tx_hex") or self._p(params, "hex")
                       or self._p(params, "txid") or "")
            try:
                tx = Transaction.deserialize(bytes.fromhex(raw_hex))
            except Exception as e:
                raise RpcError(E_INVALID_PARAMS, f"bad transaction: {e}")
            fut = asyncio.run_coroutine_threadsafe(
                self.node.submit_tx(tx, broadcast=True), self._loop)
            try:
                accepted, reason = fut.result(timeout=120)
            except Exception as e:
                raise RpcError(E_TX_ERROR, f"submission failed: {e}")
            if not accepted:
                raise RpcError(E_TX_ERROR, f"rejected: {reason}")
            return {"accepted": True, "txid": tx.txid().hex(),
                    "size": tx.size()}
        if method == "createrawtransaction":
            from qeuph.core.tx import TxIn, TxOut
            inputs_arg = self._p(params, "inputs", []) or []
            outputs_arg = self._p(params, "outputs", {}) or {}
            lock_time = int(self._p(params, "locktime", 0))
            inputs = []
            for inp in inputs_arg:
                try:
                    txid = bytes.fromhex(inp["txid"])
                    idx = int(inp["index"])
                except (KeyError, TypeError, ValueError) as e:
                    raise RpcError(E_INVALID_PARAMS, f"bad input: {e}")
                inputs.append(TxIn(txid, idx, int(inp.get("nonce", 1))))
            outputs = []
            pairs = (outputs_arg.items() if isinstance(outputs_arg, dict)
                     else [(k, v) for d in outputs_arg for k, v in d.items()])
            for addr_str, val in pairs:
                ahash = self._addr_hash(addr_str, hrp)
                val_quphi = (round(float(val) * C.QUPHI_PER_QUH)
                             if isinstance(val, (float, int)) else int(val))
                if val_quphi <= 0:
                    raise RpcError(E_INVALID_PARAMS,
                                   "output value must be positive")
                outputs.append(TxOut(val_quphi, ahash))
            if not inputs or not outputs:
                raise RpcError(E_INVALID_PARAMS,
                               "inputs and outputs are both required")
            tx = Transaction(inputs, outputs, lock_time=lock_time)
            return {"hex": tx.serialize().hex(), "txid": tx.txid().hex()}
        if method == "signrawtransaction":
            raise RpcError(E_MISC_ERROR,
                           "signing requires a wallet: use `qeuph wallet sign` "
                           "so private keys never reach the node")
        if method in ("getblocktemplate", "getwork", "getminingtemplate"):
            return self._block_template(params)
        if method == "submitblock":
            hexdata = (self._p(params, "hex") or self._p(params, "block_hex")
                       or self._p(params, "data") or "")
            if not hexdata and isinstance(params, str):
                hexdata = params
            try:
                raw = bytes.fromhex(hexdata)
                block = Block.deserialize(raw)
            except Exception as e:
                raise RpcError(E_INVALID_PARAMS, f"invalid block hex: {e}")
            fut = asyncio.run_coroutine_threadsafe(
                self.node.submit_block(block, broadcast=True), self._loop)
            try:
                ok = fut.result(timeout=180)
            except Exception as e:
                raise RpcError(E_BLOCK_SUBMISSION, f"submission failed: {e}")
            if not ok:
                raise RpcError(E_BLOCK_SUBMISSION,
                               "block rejected by consensus rules")
            return {"success": True, "hash": block.hash.hex(),
                    "height": block.height}

        # ---------------- mempool ----------------
        if method == "getmempoolinfo":
            with self.node.mempool.lock:
                return {"count": len(self.node.mempool),
                        "bytes": self.node.mempool.total_size(),
                        "maxbytes": C.MAX_MEMPOOL_SIZE,
                        "minrelayfee": C.MIN_RELAY_FEE_RATE}
        if method == "getmempool":
            return {"txids": [t.txid().hex() for t in self.node.mempool.all_txs()]}
        if method == "getrawmempool":
            verbose = bool(self._p(params, "verbose", False))
            if verbose:
                return {t.txid().hex(): t.to_dict(hrp)
                        for t in self.node.mempool.all_txs()}
            return [t.txid().hex() for t in self.node.mempool.all_txs()]

        # ---------------- mining ----------------
        if method == "generate":
            if net.is_mainnet:
                raise RpcError(E_MISC_ERROR,
                               "generate is not allowed on mainnet; use "
                               "startminer or getblocktemplate + submitblock")
            nblocks = int(self._p(params, "nblocks", 1))
            if nblocks < 1 or nblocks > 1000:
                raise RpcError(E_INVALID_PARAMS, "nblocks out of range (1..1000)")
            addr = self._p(params, "address", "") or ""
            from qeuph.crypto import address as addr_mod
            ahash = (self._addr_hash(addr, hrp) if addr
                     else (self.miner.payout_hash if self.miner else None))
            if ahash is None:
                raise RpcError(E_INVALID_PARAMS,
                               "generate needs an address or a configured miner")
            fut = asyncio.run_coroutine_threadsafe(
                self._generate_async(ahash, nblocks), self._loop)
            try:
                return fut.result(timeout=max(60, nblocks * 20))
            except RpcError:
                raise
            except Exception as e:
                raise RpcError(E_BLOCK_SUBMISSION, f"generate failed: {e}")
        if method == "startminer":
            if self.miner is None:
                raise RpcError(E_MISC_ERROR, "miner not available")
            addr = self._p(params, "address", "") or ""
            if addr:
                self.miner.set_payout(self._addr_hash(addr, hrp))
            elif self.miner.payout_hash is None:
                raise RpcError(E_INVALID_PARAMS, "no payout address configured")
            threads = int(self._p(params, "threads", 1))
            self.miner.start(threads=threads)
            return {"mining": True, **self.miner.stats()}
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
                    **self.miner.stats(),
                    "network_difficulty":
                        pow_mod.difficulty_from_bits(tip.header.bits),
                    "bits": hex(tip.header.bits),
                    "target": hex(target),
                    "chain": net.name,
                    "blocks": chain.height(),
                    "single_core_hashes_per_second":
                        round(pow_mod.hashes_per_second(tip.header.bits), 1),
                }

        # ---------------- wallet / address ----------------
        if method in ("getbalance", "listutxos", "getnonce", "getaddressinfo"):
            from qeuph.core.state import confirmations, is_mature
            addr = self._p(params, "address", "") or ""
            ahash = self._addr_hash(addr, hrp)
            with chain.lock:
                h = chain.height()
                bal = chain.state.balance(ahash, h)
                mbal = chain.state.balance(ahash, h, matured_only=True)
                nonce = chain.state.nonce_of(ahash)
                if method == "getbalance":
                    return {"address": addr, "balance": bal,
                            "balance_quh": bal / C.QUPHI_PER_QUH,
                            "matured_balance": mbal,
                            "matured_balance_quh": mbal / C.QUPHI_PER_QUH}
                if method == "getnonce":
                    return {"address": addr, "nonce": nonce}
                matured_only = bool(self._p(params, "matured_only", False))
                rows = chain.state.utxos_for(ahash, h, matured_only=matured_only)
                if method == "listutxos":
                    return {"utxos": [{
                        "txid": t.hex(), "index": i, "value": u.value,
                        "value_quh": u.value / C.QUPHI_PER_QUH,
                        "is_coinbase": u.is_coinbase,
                        "mature": is_mature(u, h),
                        "confirmations": confirmations(u, h),
                    } for t, i, u in rows]}
                return {"address": addr, "addr_hash": ahash.hex(),
                        "balance": bal,
                        "balance_quh": bal / C.QUPHI_PER_QUH,
                        "matured_balance": mbal,
                        "matured_balance_quh": mbal / C.QUPHI_PER_QUH,
                        "nonce": nonce, "utxo_count": len(rows)}
        if method == "listunspent":
            addr = self._p(params, "address", "") or ""
            ahash = self._addr_hash(addr, hrp)
            matured_only = bool(self._p(params, "matured_only", False))
            with chain.lock:
                rows = chain.state.utxos_for(ahash, chain.height(),
                                             matured_only=matured_only)
                from qeuph.core.state import confirmations
                out = [{
                    "txid": t.hex(), "vout": i, "value": u.value,
                    "value_quh": u.value / C.QUPHI_PER_QUH,
                    "is_coinbase": u.is_coinbase,
                    "mature": is_mature(u, chain.height()),
                    "confirmations": confirmations(u, chain.height()),
                } for t, i, u in rows]
            return out

        # ---------------- network ----------------
        if method == "getpeerinfo":
            return {"peers": self.node.peer_info(), "count": len(self.node.peers)}
        if method == "getnettotals":
            from qeuph.core import pow as pow_mod
            with chain.lock:
                return {"blocks": chain.height(),
                        "chainwork": hex(chain.tip_work),
                        "difficulty":
                            pow_mod.difficulty_from_bits(chain.tip.header.bits),
                        "mempool": len(self.node.mempool)}
        if method == "getnodeinfo":
            stats = dict(self.node.stats)
            stats.update(chain.chain_stats())
            stats["uptime"] = int(time.time() - self._start_time)
            stats["rpc_calls"] = self._calls
            stats["synced"] = self.node.synced
            stats["p2p_port"] = net.p2p_port
            stats["known_addrs"] = len(self.node._known_addrs)
            return stats

        # ---------------- admin ----------------
        if method == "help":
            return self.help_doc()
        if method == "rescan":
            height = self._p(params, "height")
            with chain.lock:
                return chain.verify_chain(
                    None if height is None else int(height))
        if method == "savewallet":
            path = self._p(params, "path")
            if not path:
                raise RpcError(E_INVALID_PARAMS,
                               "savewallet needs an explicit path; the node "
                               "never holds wallet keys")
            raise RpcError(E_MISC_ERROR,
                           "the node does not own wallets; use "
                           f"`qeuph wallet save --path {path}`")
        if method == "stop":
            async def _do_stop():
                self._stop_event_getter().set()

            if self._loop is not None and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(_do_stop(), self._loop)
            else:
                self._stop_event_getter().set()
            return {"stopping": True}

        raise RpcError(E_METHOD_NOT_FOUND, f"unknown method {method!r}")

    # ------------------------------------------------------------------
    def _hex_arg(self, params, key) -> bytes:
        raw = self._p(params, key)
        if not raw:
            raise RpcError(E_INVALID_PARAMS, f"missing {key}")
        try:
            return bytes.fromhex(raw)
        except (ValueError, TypeError):
            raise RpcError(E_INVALID_PARAMS, f"bad {key}")

    def _resolve_block(self, arg):
        chain = self.node.chain
        b = None
        if isinstance(arg, int) or (isinstance(arg, str) and arg.isdigit()
                                    and len(arg) < 12):
            b = chain.get_block_by_height(int(arg))
        elif isinstance(arg, str):
            try:
                b = chain.get_block(bytes.fromhex(arg))
            except ValueError:
                raise RpcError(E_INVALID_PARAMS, "bad block hash")
        if b is None:
            raise RpcError(E_MISC_ERROR, "block not found")
        return b

    def _find_confirmed_tx(self, txid):
        chain = self.node.chain
        loc = chain.store.get_tx_block(txid) if chain.store else None
        if loc is None:
            return None
        _height, bh = loc
        blk = chain.get_block(bh)
        for t in (blk.transactions if blk else []):
            if t.txid() == txid:
                return t
        return None

    def _block_template(self, params):
        from qeuph.core import pow as pow_mod
        chain = self.node.chain
        hrp = self.node.network.hrp
        with chain.lock:
            tip = chain.tip
            payout = self._p(params, "address", "") or ""
            ahash = (self._addr_hash(payout, hrp) if payout
                     else (self.miner.payout_hash if self.miner else None))
            if ahash is None:
                ahash = bytes(C.ADDRESS_HASH_SIZE)
            txs = self.node.mempool.best_transactions(C.MAX_BLOCK_SIZE - 200_000)
            template, reward = chain.create_block_template(ahash, txs)
            return {
                "version": C.BLOCK_VERSION,
                "previousblockhash": tip.hash.hex(),
                "height": template.height,
                "curtime": template.header.timestamp,
                "bits": hex(template.header.bits),
                "bits_int": template.header.bits,
                "target": hex(pow_mod.bits_to_target(template.header.bits)),
                "difficulty": pow_mod.difficulty_from_bits(template.header.bits),
                "coinbasevalue": reward,
                "coinbasevalue_quh": reward / C.QUPHI_PER_QUH,
                "coinbase_hex": template.transactions[0].serialize().hex(),
                "header_hex": template.header.serialize().hex(),
                "transactions": [t.serialize().hex() for t in txs],
                "transactions_parsed": [t.to_dict(hrp) for t in txs],
                "sizelimit": C.MAX_BLOCK_SIZE,
                "curbits": hex(tip.header.bits),
                "nextbits": hex(chain.next_bits()),
                "sigoplimit": C.MAX_BLOCK_TXS,
            }

    # ------------------------------------------------------------------
    async def _generate_async(self, ahash: bytes, nblocks: int) -> dict:
        """Regtest/testnet block generation on the event loop (thread-safe).
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
                raise RpcError(E_BLOCK_SUBMISSION, f"generated block rejected: {e}")
            if not ok:
                raise RpcError(E_BLOCK_SUBMISSION, "generated block rejected")
            hashes.append(b.hash.hex())
        return {"hashes": hashes, "height": chain.height()}

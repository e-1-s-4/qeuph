"""Qeuph node explorer, quantum wallet and miner console.

`python -m qeuph.web.server` (or `npm run start`, or `qeuph web`) serves a
single-page dashboard for a Qeuph node on http://127.0.0.1:3000/.

Design rules that keep the UI honest
------------------------------------
1. **One source of truth.**  Every read and write goes through the same
   `RPCService.dispatch` the JSON-RPC daemon uses, and the `/api/cli/*`
   routes are generated from the `qeuph` argparse tree, so the browser can
   run the *same* subcommands as the terminal.  The UI can never describe a
   capability the node does not have.
2. **The node never holds keys.**  There is no in-process wallet that can
   spend.  A wallet stays encrypted on disk; the UI asks for a passphrase per
   operation, holds the unlocked wallet only in memory for the request, and
   never returns the master seed or the recovery phrase over HTTP.  The only
   way to get a phrase out is `qeuph wallet mnemonic` on the terminal.
3. **Loopback by default.**  The HTTP server binds 127.0.0.1 and refuses to
   bind a non-loopback address without `--allow-remote`.
4. **Regtest by default.**  The embedded node runs regtest, so the "mine"
   controls cannot touch mainnet; switching to mainnet disables them.

Layout
------
GET  /                        dashboard (index.html)
GET  /api/status              node + miner + wallet summary
GET  /api/blocks[?limit=N]    recent blocks
GET  /api/block/{height|hash}
GET  /api/mempool
GET  /api/tx/{txid}
GET  /api/address/{bech32m}
GET  /api/emission            two-thirding schedule
GET  /api/peers
GET  /api/crypto              FIPS 204 self-test + parameters
GET  /api/wallet/addresses    derived addresses + balances (no secrets)
GET  /api/cli                 the CLI command tree
POST /api/rpc                 JSON-RPC 2.0 bridge (single or batch)
POST /api/cli                 run a `qeuph` subcommand
POST /api/wallet/unlock       run a wallet subcommand (create/backup/send/...)
POST /api/miner/{start,stop,threads,payout}
POST /api/generate            regtest/testnet block generation
POST /api/crypto/test         live ML-DSA-87 signature test
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import io
import json
import logging
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse, urlsplit

from qeuph import constants as C
from qeuph.cli import main as cli_main
from qeuph.config import Network, get_network
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.network.rpc import RPCService
from qeuph.node.node import QNode
from qeuph.services.miner import SoloMiner
from qeuph.wallet import keystore

logger = logging.getLogger("qeuph.web")

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))       # .../qeuph/web
_REPO_ROOT = os.path.dirname(os.path.dirname(_PKG_DIR))     # <repo>
# the UI ships inside the package, so it works from an installed wheel and
# from a source checkout alike
STATIC_DIRS = [
    os.path.join(_PKG_DIR, "static"),
    os.path.join(_REPO_ROOT, "web"),          # legacy top-level web/ directory
]
# Deliberately NOT os.getcwd(): serve_static allowlists by filename, so a
# cwd containing an index.html would serve it from the trusted loopback
# origin - and a wallet written to that path by another route would then be
# reachable at the site root.
STATIC_FILES = ("index.html", "app.js", "style.css", "favicon.svg")


# ---------------------------------------------------------------------------
# embedded node
# ---------------------------------------------------------------------------
class NodeManager:
    """Owns the chain, mempool, p2p node, miner and RPC facade for the UI.

    The network profile is IMMUTABLE (frozen dataclass), so switching networks
    derives a new profile with `dataclasses.replace` and tears the old node
    down first; the previous implementation mutated a module-level singleton
    and leaked a running P2P listener on every switch.
    """

    def __init__(self, network_name: str = "regtest",
                 data_root: Optional[str] = None, start_node: bool = True,
                 port_offset: int = 0):
        self.lock = threading.RLock()
        self.port_offset = port_offset
        self.data_root = data_root or os.path.join(
            os.environ.get("TMPDIR", "/tmp"), "qeuph-web")
        self.network_name = network_name
        self.chain: Optional[ChainManager] = None
        self.mempool: Optional[Mempool] = None
        self.node: Optional[QNode] = None
        self.miner: Optional[SoloMiner] = None
        self.rpc: Optional[RPCService] = None
        self.network: Network = get_network(network_name)
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self._stop_evt: Optional[asyncio.Event] = None
        self.start_time = time.time()
        self.started_node = False
        if start_node:
            self.open(network_name)
        else:
            self.network = get_network(network_name)

    # ------------------------------------------------------------------
    def data_dir(self, network_name: str) -> str:
        d = os.path.join(self.data_root, network_name)
        os.makedirs(d, exist_ok=True)
        return d

    def network_for(self, network_name: str) -> Network:
        base = get_network(network_name)
        # UI ports are derived from the profile so two web servers can run
        # side by side on one host; port_offset lets a caller move them again.
        offset = self.port_offset + {
            "mainnet": 0, "testnet": 1000, "regtest": 2000}[network_name]
        return dataclasses.replace(
            base,
            data_dir=self.data_dir(network_name),
            p2p_port=base.p2p_port + offset,
            rpc_port=base.rpc_port + offset,
        )

    # ------------------------------------------------------------------
    def open(self, network_name: str):
        """(Re)open the embedded node on `network_name`, stopping the old one."""
        with self.lock:
            self.close()
            self.network_name = network_name
            self.network = self.network_for(network_name)
            self.chain = ChainManager(self.network)
            self.mempool = Mempool(self.chain.state_provider(),
                                   fee_rate=C.MIN_RELAY_FEE_RATE,
                                   height_fn=self.chain.height,
                                   mtp_fn=self.chain.median_time_past)
            self.node = QNode(self.network, self.chain, self.mempool)
            self.miner = SoloMiner(self.node)
            self._stop_evt = asyncio.Event()
            self._ensure_loop()
            self.miner.attach_loop(self._loop)
            # the embedded node gets a REAL loopback JSON-RPC listener, so
            # `qeuph wallet ... --rpc http://127.0.0.1:<rpc_port>/` works
            # against the browser's node exactly as it does against a
            # standalone daemon
            self.rpc = RPCService(self.node, self.miner,
                                  C.DEFAULT_RPC_HOST, self.network.rpc_port,
                                  lambda: self._stop_evt)
            self.rpc.start_background(self._loop)
            self.started_node = True
            logger.info("embedded node opened on %s at height %d "
                        "(rpc %s)", network_name, self.chain.height(),
                        self.rpc.url)
            return self.status()

    def _ensure_loop(self):
        if self._loop and not self._loop.is_closed():
            return
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(
            target=self._run_loop, daemon=True, name="qeuph-web-loop")
        self._loop_thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def close(self):
        if self.miner is not None and self.miner.is_mining():
            self.miner.stop()
        if self.rpc is not None:
            self.rpc.stop()
            self.rpc = None
        if self.node is not None and self._loop is not None \
                and not self._loop.is_closed():
            try:
                fut = asyncio.run_coroutine_threadsafe(self.node.stop(),
                                                      self._loop)
                fut.result(timeout=8)
            except Exception:
                pass
        if self.chain is not None:
            self.chain.close()
        self.node = None
        self.chain = None
        self.mempool = None
        self.miner = None
        self.started_node = False

    def submit_coro(self, coro, timeout: float = 180.0):
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)

    # ------------------------------------------------------------------
    def wallet_path(self, network_name: Optional[str] = None) -> str:
        return os.path.join(self.data_dir(network_name or self.network_name),
                            "wallet.json")

    def wallet_info(self) -> dict:
        path = self.wallet_path()
        out = {"path": path, "exists": os.path.exists(path)}
        if out["exists"]:
            try:
                doc = keystore.load_wallet_doc(path)
                out.update({"network": doc.get("network"),
                            "cipher": doc.get("cipher"),
                            "kdf": doc.get("kdf", {}).get("name"),
                            "kdf_iterations":
                                doc.get("kdf", {}).get("iterations"),
                            "next_index": doc.get("next_index", 0),
                            "encrypted": "aes" in doc})
            except Exception as e:
                out["error"] = str(e)
        return out

    def status(self) -> dict:
        from qeuph.core import pow as pow_mod
        from qeuph.core import reward as reward_mod
        with self.lock:
            if self.chain is None:
                return {"network": self.network_name, "node": None}
            tip = self.chain.tip
            h = tip.height
            st = {
                "network": self.network.name,
                "hrp": self.network.hrp,
                "node": "embedded",
                "height": h,
                "best_hash": tip.hash.hex(),
                "genesis_hash": self.chain.genesis.hash.hex(),
                "bits": hex(tip.header.bits),
                "difficulty": pow_mod.difficulty_from_bits(tip.header.bits),
                "chainwork": hex(self.chain.tip_work),
                "mediantime": self.chain.median_time_past(),
                "reward_quphi": self.chain.block_reward(),
                "reward_quh": self.chain.block_reward() / C.QUPHI_PER_QUH,
                "epoch": reward_mod.epoch_at(h),
                "mempool_count": len(self.mempool),
                "mempool_bytes": self.mempool.total_size(),
                "utxos": len(self.chain.state.utxos),
                "peers": len(self.node.peers),
                "synced": self.node.synced,
                "orphans": self.chain.orphan_count(),
                "reorgs": self.chain.reorg_count,
                "block_time": self.network.block_time,
                "retarget_interval": self.network.retarget_interval,
                "mining_allowed": not self.network.is_mainnet,
                "rpc_url": self.rpc.url if self.rpc else None,
                "backend": ml_dsa.backend_name(),
                "version": C.VERSION,
                "uptime": int(time.time() - self.start_time),
                "data_dir": self.network.data_dir,
            }
            st.update({"mining": self.miner.is_mining(),
                       "hashrate": round(self.miner.hashrate(), 2),
                       "blocks_mined": self.miner.blocks_mined,
                       "threads": self.miner.threads,
                       "payout_address": self.miner.payout_address_hex})
            st["wallet"] = self.wallet_info()
            return st

    def address_report(self, count: int = 5, index: Optional[int] = None,
                       start: int = 0) -> dict:
        """Balances for the first `count` derived addresses of the on-disk
        wallet.  Only public data - never the seed or the phrase."""
        path = self.wallet_path()
        if not os.path.exists(path):
            return {"exists": False, "path": path, "addresses": []}
        with self.lock:
            if self.chain is None:
                return {"exists": True, "path": path, "addresses": []}
            h = self.chain.height()
            try:
                doc = keystore.load_wallet_doc(path)
            except Exception as e:
                return {"exists": True, "path": path, "error": str(e),
                        "addresses": []}
            # public keys and addresses are derived from the seed, which stays
            # sealed; the caller may drive them through the CLI routes instead
            rows = []
            for i in range(start, start + count):
                try:
                    addr = derive_address_from_wallet(
                        path, i, passphrase=None, hrp=self.network.hrp)
                except Exception:
                    addr = None
                if addr is None:
                    break
                ahash = addr_mod.address_to_hash(addr, self.network.hrp)
                if ahash is None:
                    break
                bal = self.chain.state.balance(ahash, h)
                mat = self.chain.state.balance(ahash, h, matured_only=True)
                rows.append({
                    "index": i,
                    "address": addr,
                    "balance_quphi": bal,
                    "balance_quh": bal / C.QUPHI_PER_QUH,
                    "matured_quphi": mat,
                    "matured_quh": mat / C.QUPHI_PER_QUH,
                    "nonce": self.chain.state.nonce_of(ahash),
                })
            return {"exists": True, "path": path,
                    "network": doc.get("network"),
                    "cipher": doc.get("cipher"),
                    "next_index": doc.get("next_index", 0),
                    "addresses": rows}


def derive_address_from_wallet(path: str, index: int,
                               passphrase: Optional[str] = None,
                               hrp: str = "quh") -> Optional[str]:
    """Derive one address from a wallet file.

    A wallet sealed with a real passphrase cannot be read without it, so this
    returns None and the UI asks for the passphrase through the
    `/api/wallet` route, which keeps the seed in memory only for the duration
    of that request.  A wallet created with an empty passphrase (or
    `--unencrypted`) derives without one.
    """
    from qeuph.wallet.keys import derive_key
    doc = keystore.load_wallet_doc(path)
    use_hrp = hrp or doc.get("hrp", "quh")
    try:
        seed = keystore.load_wallet(path, passphrase)
    except keystore.WalletError:
        return None
    return addr_mod.hash_to_address(derive_key(seed, index, use_hrp).addr_hash,
                                    use_hrp)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class HttpError(Exception):
    """A route helper refused the request.

    Raised instead of calling ``send_error_json`` from inside a helper whose
    result is itself passed to ``send_json``: that pattern emitted TWO
    complete HTTP responses onto one keep-alive connection (the inner 400
    plus an outer 200 carrying ``null``), and the second response's status
    line was then read as the next request on the socket.
    """

    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code


# Serialises in-process CLI execution.  `contextlib.redirect_stdout` swaps a
# PROCESS-global, so two concurrent /api/cli requests in a ThreadingHTTPServer
# would otherwise interleave each other's output - and capture the embedded
# node's own logging from unrelated threads.
_CLI_LOCK = threading.Lock()

NODE: Optional[NodeManager] = None
CLI_TREE: Optional[dict] = None
ALLOW_REMOTE = False

# Bounds for caller-supplied list sizes.  These views do real work per item
# (a PBKDF2 unlock plus an ML-DSA-87 keygen per derived address), so an
# unbounded `count` is an unauthenticated CPU/thread wedge.
MAX_ADDRESS_COUNT = 50
MAX_BLOCK_LIMIT = 50
# Same cap the JSON-RPC transport enforces (rpc.MAX_BATCH), so the web bridge
# cannot be used to bypass it.
MAX_WEB_BATCH = 32
MAX_BODY_BYTES = 8 * 1024 * 1024


class QeuphHttpHandler(BaseHTTPRequestHandler):
    server_version = f"qeuph/{C.VERSION}"
    protocol_version = "HTTP/1.1"
    # Without this an idle keep-alive connection pins a worker thread in
    # rfile.readline() forever (slow-loris / thread exhaustion).
    timeout = 120

    # -- plumbing -------------------------------------------------------
    def log_message(self, fmt, *args):
        pass

    def send_cors(self):
        # The UI is served from this same origin, so it needs no
        # cross-origin grant at all.  `Access-Control-Allow-Origin: *` on an
        # endpoint that can spend a wallet and stop the node means any page
        # the operator visits can drive it with a readable response; the
        # browser is not blocked from reaching loopback.  Same-origin only.
        origin = self.headers.get("Origin")
        host = self.headers.get("Host", "")
        if origin and _same_origin(origin, host):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods",
                             "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_json(self, data, code: int = 200):
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_cors()
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        return None

    def send_error_json(self, message: str, code: int = 400):
        return self.send_json({"error": message, "ok": False}, code)

    def read_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if length > MAX_BODY_BYTES:
            # A transport fault, so it gets a 4xx - not a 200 with a
            # JSON-RPC application error.  The body is drained and the
            # connection closed: leaving those bytes unread desynchronises a
            # keep-alive stream, because they are then parsed as the next
            # request line.
            self._drain(length)
            self.close_connection = True
            raise HttpError(f"request body too large (max {MAX_BODY_BYTES} "
                            f"bytes)", 413)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception:
            return {}
        return doc if isinstance(doc, dict) else {"value": doc}

    def _drain(self, length: int):
        remaining = min(int(length), MAX_BODY_BYTES)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

    # -- routing --------------------------------------------------------
    def _int_param(self, parsed, name: str, default: int, lo: int, hi: int):
        """Bounded integer query parameter; a bad or huge value is a 400."""
        raw = (parse_qs(parsed.query).get(name) or [str(default)])[0]
        try:
            n = int(raw)
        except (TypeError, ValueError):
            raise HttpError(f"{name} must be an integer, got {raw!r}", 400)
        return max(lo, min(hi, n))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            if path in ("/", "/index.html"):
                return self.serve_static("index.html")
            if path in ("/favicon.ico", "/favicon.svg"):
                return self.serve_static("favicon.svg", "image/svg+xml")
            if path == "/app.js":
                return self.serve_static("app.js", "application/javascript")
            if path == "/style.css":
                return self.serve_static("style.css", "text/css")
            if path == "/api/status":
                return self.send_json(NODE.status())
            if path == "/api/blocks":
                limit = self._int_param(parsed, "limit", 15, 1, MAX_BLOCK_LIMIT)
                return self.send_json(self.blocks(limit))
            if path == "/api/mempool":
                return self.send_json(self.mempool_info())
            if path == "/api/peers":
                return self.send_json({"peers": NODE.node.peer_info()
                                       if NODE.node else []})
            if path == "/api/emission":
                return self.send_json(self.emission())
            if path == "/api/crypto":
                return self.send_json(self.crypto_info())
            if path == "/api/wallet/addresses":
                count = self._int_param(parsed, "count", 5, 1,
                                        MAX_ADDRESS_COUNT)
                return self.send_json(NODE.address_report(count))
            if path == "/api/cli":
                return self.send_json(cli_tree())
            if path.startswith("/api/block/"):
                return self.send_json(self.one_block(
                    path[len("/api/block/"):]))
            if path.startswith("/api/tx/"):
                return self.send_json(self.one_tx(path[len("/api/tx/"):]))
            if path.startswith("/api/address/"):
                return self.send_json(self.one_address(
                    path[len("/api/address/"):]))
            return self.send_error_json("not found", 404)
        except HttpError as e:
            return self.send_error_json(e.message, e.code)
        except Exception as e:                       # never kill the server
            logger.exception("GET %s failed", path)
            return self.send_error_json(f"internal error: {e}", 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            data = self.read_body()
        except HttpError as e:
            return self.send_error_json(e.message, e.code)
        try:
            if path == "/api/rpc":
                return self.send_json(self.rpc_bridge(data))
            if path == "/api/cli":
                return self.send_json(self.run_cli(data, wallet=False))
            if path == "/api/wallet":
                return self.send_json(self.run_cli(data, wallet=True))
            if path == "/api/miner/start":
                return self.send_json(self.miner_start(data))
            if path == "/api/miner/stop":
                NODE.miner.stop()
                return self.send_json({"ok": True, "mining": False,
                                       "miner": NODE.miner.stats()})
            if path == "/api/miner/threads":
                th = max(1, min(16, int(data.get("threads", 1))))
                NODE.miner.set_threads(th)
                return self.send_json({"ok": True, "threads": th,
                                       "miner": NODE.miner.stats()})
            if path == "/api/miner/payout":
                # Setting a payout address is what makes the miner runnable,
                # so it is part of the mainnet mining surface and is guarded
                # exactly like /api/miner/start.  Guarding only the start
                # route left `POST /api/rpc {"method":"startminer"}` as a
                # way around it.
                if NODE.network.is_mainnet:
                    raise HttpError(
                        "the UI will not arm a solo miner on mainnet; use "
                        "`qeuph node --network mainnet --mine ADDR` from the "
                        "terminal", 403)
                payout = str(data.get("address", "")).strip()
                ahash = addr_mod.address_to_hash(payout, NODE.network.hrp)
                if ahash is None:
                    raise HttpError(
                        f"invalid {NODE.network.hrp} address", 400)
                NODE.miner.set_payout(ahash)
                return self.send_json({"ok": True, "payout": payout})
            if path == "/api/generate":
                return self.send_json(self.generate(data))
            if path == "/api/network":
                name = str(data.get("network", "regtest"))
                if name not in ("mainnet", "testnet", "regtest"):
                    raise HttpError(f"unknown network {name}")
                if NODE.miner.is_mining():
                    NODE.miner.stop()
                status = NODE.open(name)
                return self.send_json({"ok": True, "status": status})
            if path == "/api/crypto/test":
                return self.send_json(self.crypto_test(data))
            return self.send_error_json("not found", 404)
        except HttpError as e:
            return self.send_error_json(e.message, e.code)
        except PermissionError as e:
            return self.send_error_json(str(e), 403)
        except Exception as e:
            logger.exception("POST %s failed", path)
            return self.send_error_json(str(e), 500)

    # -- static ---------------------------------------------------------
    def serve_static(self, name: str, content_type: str = "text/html"):
        if name not in STATIC_FILES:
            return self.send_error_json("not found", 404)
        for d in STATIC_DIRS:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", f"{content_type}; charset=utf-8")
                self.send_cors()
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
        return self.send_error_json(f"{name} not found (looked in "
                                    f"{', '.join(STATIC_DIRS)})", 404)

    # -- data views -----------------------------------------------------
    def blocks(self, limit: int) -> dict:
        limit = max(1, min(50, limit))
        chain = NODE.chain
        out = []
        with chain.lock:
            for h in range(chain.height(), max(-1, chain.height() - limit), -1):
                b = chain.get_block_by_height(h)
                if b is None:
                    continue
                out.append(b.summary(NODE.network.hrp,
                                     chain.height() - h + 1))
        return {"blocks": out, "total_height": chain.height()}

    def one_block(self, target: str) -> dict:
        b = None
        if target.isdigit():
            b = NODE.chain.get_block_by_height(int(target))
        else:
            try:
                b = NODE.chain.get_block(bytes.fromhex(target))
            except ValueError:
                pass
        if b is None:
            return {"error": "block not found", "ok": False}
        d = b.to_dict(NODE.network.hrp)
        with NODE.chain.lock:
            d["confirmations"] = NODE.chain.height() - b.height + 1
        return d

    def mempool_info(self) -> dict:
        mp = NODE.mempool
        with mp.lock:
            txs = [t.to_dict(NODE.network.hrp) for t in mp.all_txs()]
        return {"count": len(txs), "bytes": mp.total_size(),
                "maxbytes": C.MAX_MEMPOOL_SIZE,
                "relayfee": C.MIN_RELAY_FEE_RATE, "transactions": txs}

    def one_tx(self, txid_hex: str) -> dict:
        try:
            txid = bytes.fromhex(txid_hex)
        except ValueError:
            return {"error": "invalid txid", "ok": False}
        tx = NODE.mempool.get_tx(txid)
        if tx is not None:
            d = tx.to_dict(NODE.network.hrp)
            d["mempool"] = True
            return d
        loc = NODE.chain.store.get_tx_block(txid) if NODE.chain.store else None
        if loc:
            height, bh = loc
            blk = NODE.chain.get_block(bh)
            for t in (blk.transactions if blk else []):
                if t.txid() == txid:
                    d = t.to_dict(NODE.network.hrp)
                    d.update({"height": height, "block_hash": bh.hex(),
                              "confirmations": NODE.chain.height() - height + 1})
                    return d
        return {"error": "transaction not found", "ok": False}

    def one_address(self, addr: str) -> dict:
        hrp = NODE.network.hrp
        ahash = addr_mod.address_to_hash(addr, hrp)
        if ahash is None or len(ahash) != C.ADDRESS_HASH_SIZE:
            return {"error": f"invalid {hrp} address", "ok": False}
        from qeuph.core.state import confirmations, is_mature
        with NODE.chain.lock:
            h = NODE.chain.height()
            bal = NODE.chain.state.balance(ahash, h)
            mat = NODE.chain.state.balance(ahash, h, matured_only=True)
            nonce = NODE.chain.state.nonce_of(ahash)
            rows = NODE.chain.state.utxos_for(ahash, h)
        return {
            "address": addr, "network": NODE.network.name, "hrp": hrp,
            "addr_hash": ahash.hex(),
            "balance_quphi": bal, "balance_quh": bal / C.QUPHI_PER_QUH,
            "matured_quphi": mat, "matured_quh": mat / C.QUPHI_PER_QUH,
            "nonce": nonce, "utxos_count": len(rows),
            "utxos": [{
                "txid": t.hex(), "index": i,
                "value_quphi": u.value, "value_quh": u.value / C.QUPHI_PER_QUH,
                "is_coinbase": u.is_coinbase,
                "mature": is_mature(u, h),
                "confirmations": confirmations(u, h),
            } for t, i, u in rows[:100]],
        }

    def emission(self) -> dict:
        from qeuph.core import reward as reward_mod
        rows = [{
            "epoch": e, "start_height": h, "reward_quphi": r,
            "reward_quh": rq,
            "cumulative_quh": cum / C.QUPHI_PER_QUH,
        } for e, h, r, rq, cum in reward_mod.emission_table()]
        exact = reward_mod.exact_total_emission()
        return {"cap_quh": C.MAX_SUPPLY_QUH, "decimals": C.DECIMALS,
                "epochs": reward_mod.epoch_count(),
                "final_reward_height": reward_mod.last_reward_height(),
                "exact_quphi": exact,
                "exact_quh": exact / C.QUPHI_PER_QUH,
                "table": rows}

    def crypto_info(self) -> dict:
        from qeuph.crypto import fips204
        return {
            "signature_scheme": "ML-DSA-87 (FIPS 204 final)",
            "security_category": 5,
            "backend": ml_dsa.backend_name(),
            "pk_size": ml_dsa.PK_SIZE, "sk_size": ml_dsa.SK_SIZE,
            "sig_size": ml_dsa.SIG_SIZE, "seed_size": ml_dsa.SEED_SIZE,
            "hash": "double SHA3-512 (FIPS 202)",
            "address": "Bech32m (BIP-350) over a 512-bit double SHA3-512 digest",
            "q": fips204.Q, "k": fips204.K, "l": fips204.L,
            "eta": fips204.ETA, "tau": fips204.TAU,
            "gamma1": fips204.GAMMA1, "gamma2": fips204.GAMMA2,
            "omega": fips204.OMEGA, "zeta": fips204.ZETA,
            "reference_implementation": "qeuph/crypto/fips204.py (pure Python)",
            "cross_verified": "against OpenSSL/AWS-LC ML-DSA",
        }

    def crypto_test(self, data: dict) -> dict:
        msg = str(data.get("message", "Qeuph quantum-resistant transaction")
                  ).encode()
        seed, pk, sk = ml_dsa.generate_keypair()
        t0 = time.time()
        sig = ml_dsa.sign_with_seed(seed, msg)
        sign_ms = (time.time() - t0) * 1000
        t0 = time.time()
        ok = ml_dsa.verify(pk, msg, sig)
        verify_ms = (time.time() - t0) * 1000
        tamper = ml_dsa.verify(pk, msg + b"TAMPERED", sig)
        t0 = time.time()
        pure = ml_dsa.verify_pure(pk, msg, sig)
        pure_ms = (time.time() - t0) * 1000
        return {
            "message": msg.decode(errors="replace"),
            "pk_bytes": len(pk), "sk_bytes": len(sk),
            "sig_bytes": len(sig),
            "pk_prefix": pk.hex()[:64],
            "sig_prefix": sig.hex()[:64],
            "verified": ok, "verified_pure_python": pure,
            "tamper_detected": not tamper,
            "sign_ms": round(sign_ms, 3),
            "verify_ms": round(verify_ms, 3),
            "verify_pure_ms": round(pure_ms, 3),
            "algorithm": "ML-DSA-87 (FIPS 204), NIST category 5",
        }

    # -- actions --------------------------------------------------------
    def rpc_bridge(self, data: dict) -> dict:
        if NODE.rpc is None:
            return {"ok": False, "error": "node is not running"}
        # single call or a batch, exactly like the JSON-RPC daemon
        if isinstance(data.get("batch"), list):
            batch = data["batch"]
            if len(batch) > MAX_WEB_BATCH:
                return {"ok": False,
                        "error": f"batch larger than {MAX_WEB_BATCH}"}
            return {"ok": True, "batch": [self._rpc_one(r) for r in batch]}
        return self._rpc_one(data)

    def _rpc_one(self, req: dict) -> dict:
        method = str(req.get("method", ""))
        params = req.get("params", {}) or {}
        rid = req.get("id", 1)
        if NODE.rpc is None:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32603, "message": "node is not running"}}
        try:
            return {"jsonrpc": "2.0", "id": rid,
                    "result": NODE.rpc.dispatch(method, params)}
        except Exception as e:
            code = getattr(e, "code", -32000)
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": code, "message": str(e)}}

    def miner_start(self, data: dict) -> dict:
        if NODE.network.is_mainnet:
            raise HttpError(
                "the UI will not start a solo miner on mainnet; use "
                "`qeuph node --network mainnet --mine ADDR` from the "
                "terminal", 403)
        payout = str(data.get("payout", "")).strip()
        if payout:
            ahash = addr_mod.address_to_hash(payout, NODE.network.hrp)
            if ahash is None:
                raise HttpError(f"invalid {NODE.network.hrp} address", 400)
            NODE.miner.set_payout(ahash)
        if NODE.miner.payout_hash is None:
            raise HttpError(
                "set a payout address first (POST /api/miner/payout)", 400)
        threads = max(1, min(16, int(data.get("threads", NODE.miner.threads))))
        NODE.miner.start(threads=threads)
        return {"ok": True, "mining": True, "miner": NODE.miner.stats()}

    def generate(self, data: dict) -> dict:
        if NODE.network.is_mainnet:
            raise HttpError("generate is not allowed on mainnet", 403)
        n = max(1, min(200, int(data.get("count", 1))))
        payout = str(data.get("address", "")).strip()
        if payout:
            ahash = addr_mod.address_to_hash(payout, NODE.network.hrp)
            if ahash is None:
                raise HttpError(f"invalid {NODE.network.hrp} address", 400)
        else:
            ahash = NODE.miner.payout_hash
        if ahash is None:
            raise HttpError("no payout address", 400)
        res = NODE.submit_coro(NODE.rpc._generate_async(ahash, n),
                               timeout=max(60, n * 20))
        return {"ok": True, "count": n, "hashes": res["hashes"],
                "height": res["height"]}

    def run_cli(self, data: dict, wallet: bool) -> dict:
        """Run a `qeuph` subcommand with argv, capturing stdout.

        This is what keeps the UI in lockstep with the CLI: the browser
        submits the same argv string the terminal would, and the harness only
        injects the flags the chosen subcommand actually declares.
        """
        args = data.get("args")
        if isinstance(args, list):
            argv = [str(a) for a in args]
        elif isinstance(args, str):
            argv = args.split()
        else:
            argv = []
        passphrase = data.get("passphrase")
        if passphrase is not None:
            argv += ["--passphrase", str(passphrase)]
        allowed = ALLOWED_WALLET_CMDS if wallet else ALLOWED_CLI_CMDS
        if not argv or argv[0] not in allowed:
            return {"ok": False, "args": redact_argv(argv),
                    "error": f"only {sorted(allowed)} may be run here"}
        if wallet and _exports_secret(argv):
            return {"ok": False, "args": redact_argv(argv),
                    "error": "the recovery phrase and the master seed are "
                             "never returned over HTTP; run "
                             "`qeuph wallet mnemonic` (or "
                             "`qeuph wallet backup --out-mnemonic`) in a "
                             "terminal you trust"}
        # Per-subcommand allowlist: the group is not enough on its own.
        if wallet and argv[0] == "wallet":
            sub = _subcommand_arg(argv)
            if sub is not None and sub not in ALLOWED_WALLET_SUBCOMMANDS:
                return {"ok": False, "args": redact_argv(argv),
                        "error": f"wallet {sub!r} is not available over HTTP "
                                 f"(allowed: "
                                 f"{sorted(ALLOWED_WALLET_SUBCOMMANDS)}); use "
                                 f"the `qeuph wallet` command in a terminal"}
        if argv[0] == "chain":
            sub = _subcommand_arg(argv)
            if sub is not None and sub not in ALLOWED_CHAIN_SUBCOMMANDS:
                return {"ok": False, "args": redact_argv(argv),
                        "error": f"chain {sub!r} is not available over HTTP "
                                 f"(allowed: "
                                 f"{sorted(ALLOWED_CHAIN_SUBCOMMANDS)}); it "
                                 f"rewrites the node's database"}
        opts = _subcommand_options(argv)
        if "--network" in opts and not _has_flag(argv, "--network"):
            argv += ["--network", NODE.network.name]
        if "--data-dir" in opts and not _has_flag(argv, "--data-dir") \
                and NODE.chain is not None:
            # point offline chain tools at the embedded node's database so
            # they report the same chain the browser is looking at
            argv += ["--data-dir", NODE.network.data_dir]
        if wallet:
            # A caller-supplied --path selects WHICH wallet file to use, so
            # the feature is kept; it is constrained instead of ignored.  The
            # danger was never the path itself but writing a wallet document
            # over something that matters (the embedded node's chain.db, for
            # instance), so the target must be a .json file and must not land
            # on the node's own data directory.
            if "--path" in opts:
                supplied = _flag_value(argv, "--path")
                if supplied is not None:
                    target = os.path.abspath(supplied)
                    if not target.lower().endswith(".json"):
                        raise HttpError(
                            "wallet path must name a .json file", 400)
                    data_dir = os.path.abspath(NODE.network.data_dir)
                    if os.path.commonpath([target, data_dir]) == data_dir \
                            and target != os.path.abspath(NODE.wallet_path()):
                        raise HttpError(
                            "refusing to write a wallet over the node's own "
                            "data directory", 403)
                else:
                    argv += ["--path", NODE.wallet_path()]
            if "--rpc" in opts and not _has_flag(argv, "--rpc") \
                    and NODE.rpc is not None:
                argv += ["--rpc", NODE.rpc.url]
        # One CLI run at a time: redirect_stdout/stderr mutate process-global
        # state, and the embedded node keeps logging from the event loop.
        with _CLI_LOCK:
            buf, err = io.StringIO(), io.StringIO()
            # Never let a CLI subcommand block on a prompt: the server owns
            # the real stdin, and getpass there would hang the worker thread
            # forever instead of failing the request.
            no_tty = io.StringIO()
            old_stdin = sys.stdin
            try:
                sys.stdin = no_tty
                with contextlib.redirect_stdout(buf), \
                        contextlib.redirect_stderr(err):
                    cli_main.main(argv)
                ok, code = True, 0
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else (0 if e.code is None
                                                               else 1)
                ok = code == 0
                if not isinstance(e.code, int) and e.code:
                    err.write(str(e.code) + "\n")
            except Exception as e:
                logger.exception("cli %s failed", redact_argv(argv))
                return {"ok": False, "args": redact_argv(argv),
                        "error": str(e)}
            finally:
                sys.stdin = old_stdin
        return {"ok": ok, "exit_code": code, "args": redact_argv(argv),
                "stdout": redact_secrets(buf.getvalue()),
                "stderr": redact_secrets(err.getvalue())}


# argv elements that carry secret material and must never be echoed
_SECRET_FLAGS = {"--passphrase", "--from-mnemonic", "--new-passphrase",
                 "--old-passphrase"}


def redact_argv(argv) -> list:
    """Copy of argv with secret values masked.

    The response body used to contain the literal `argv`, which carried the
    wallet passphrase (appended by this handler) and any recovery phrase
    passed to `wallet restore --from-mnemonic`.  Both therefore landed in
    browser devtools, proxy logs and any response cache.
    """
    out = []
    mask_next = False
    for a in argv:
        if mask_next:
            out.append("<redacted>")
            mask_next = False
            continue
        if a in _SECRET_FLAGS:
            out.append(a)
            mask_next = True
            continue
        if a.startswith("--") and "=" in a:
            flag = a.split("=", 1)[0]
            if flag in _SECRET_FLAGS:
                out.append(f"{flag}=<redacted>")
                continue
        out.append(a)
    return out


# BIP-39 phrases (12/15/18/21/24 words) and the hex master seed the CLI can
# print.  Case-insensitive and colon-optional because the repository's own
# labels are "Master Seed   <hex>" (no colon) and a phrase may be printed in
# any case; a redaction that only matched one exact spelling is no redaction.
_MNEMONIC_RE = re.compile(
    r"\b(?:[a-z]{3,8}[\s,]+){11,23}[a-z]{3,8}\b", re.IGNORECASE)
_MASTER_SEED_RE = re.compile(
    r"(master\s+seed\b[^\n]*?)([0-9a-f]{32,})", re.IGNORECASE)
_SECRET_KEY_RE = re.compile(
    r"(secret\s+key\b[^\n]*?)([0-9a-f]{32,})", re.IGNORECASE)


def redact_secrets(text: str) -> str:
    """Strip recovery phrases, master seeds and secret keys from CLI output
    bound for HTTP."""
    text = _MNEMONIC_RE.sub(
        "[recovery phrase redacted - run `qeuph wallet mnemonic` in a "
        "terminal]", text)
    text = _MASTER_SEED_RE.sub(r"\1[redacted]", text)
    return _SECRET_KEY_RE.sub(r"\1[redacted]", text)


def _exports_secret(argv) -> bool:
    """True when the subcommand would print key material.

    The pairing is explicit because several subcommands legitimately accept
    an option that merely *consumes* a phrase (`wallet show --from-mnemonic`
    names a wallet file to read), so testing for the presence of the option
    name alone flags harmless invocations.

    Abbreviations cannot be used to slip past this: the parser tree is built
    with allow_abbrev=False, so `--out-mnem` is a hard parse error rather
    than a synonym for `--out-mnemonic`.
    """
    if argv[:2] == ["wallet", "mnemonic"]:
        return True
    if argv[:2] == ["wallet", "backup"] and _has_flag(argv, "--out-mnemonic"):
        return True
    if argv[:2] == ["wallet", "show"] and _has_flag(argv, "--show-seed"):
        return True
    return False


def _is_loopback(host: str) -> bool:
    """True when `host` provably resolves to a loopback address.

    A string comparison against ("127.0.0.1", "::1", "localhost") trusts the
    name: a hosts entry pointing "localhost" off-loopback would bind
    publicly, and other loopback addresses such as 127.0.0.2 were refused for
    no reason.  `ipaddress` decides from the address itself.
    """
    import ipaddress
    h = (host or "").strip()
    if not h:
        return False          # "" binds every interface
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        pass
    if h.lower() in ("localhost", "localhost.localdomain", "ip6-localhost"):
        return True
    return False


def _flag_value(argv, flag: str) -> Optional[str]:
    """The value of `--flag value` or `--flag=value` in argv, else None."""
    for i, a in enumerate(argv):
        if a == flag and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return None


def _subcommand_arg(argv) -> Optional[str]:
    """The subcommand named in argv[1], or None when argv names no group."""
    return argv[1] if len(argv) > 1 and not argv[1].startswith("-") else None


def _same_origin(origin: str, host: str) -> bool:
    """True when an Origin header refers to the Host we are serving."""
    if not origin or "://" not in origin:
        return False
    try:
        o = urlsplit(origin)
    except ValueError:
        return False
    o_host = o.netloc.split("@")[-1].lower()
    h = (host or "").split("@")[-1].lower()
    if o.scheme not in ("http", "https"):
        return False
    return o_host == h or o_host == h.split(":")[0]


def _subcommand_options(argv) -> set:
    """Long-option names accepted by the subcommand named in argv."""
    parser = cli_main.build_parser()
    node = None
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            node = action
            break
    if node is None:
        return set()
    # argv[0] is the top-level command, argv[1] the subcommand
    cur = node.choices.get(argv[0])
    if cur is None:
        return set()
    for a in argv[1:]:
        if a.startswith("-"):
            break
        for action in cur._actions:
            if isinstance(action, argparse._SubParsersAction):
                nxt = action.choices.get(a)
                if nxt is not None:
                    cur = nxt
                    break
    return {"--" + a.dest.replace("_", "-") for a in cur._actions
            if a.dest != "help"}


def _has_flag(argv, flag: str) -> bool:
    return any(a == flag or a.startswith(flag + "=") for a in argv)


# `node` and `web` are deliberately NOT here: a browser must not be able to
# start a second daemon on the same data directory, nor nest a web server.
#
# `rpc` is also excluded: the browser already has POST /api/rpc, and the
# command's `--url` is an arbitrary outbound URL, so allowing it here turned
# this endpoint into an SSRF primitive (and, because that subcommand takes
# no --network, it silently targeted the MAINNET RPC port rather than the
# embedded node).
#
# `mine` is excluded for the same reason as the miner routes: it is an
# unbounded CPU/thread burner reachable without a flag.
ALLOWED_CLI_CMDS = {"chain", "genesis", "emission",
                    "address", "crypto", "version"}
# `chain truncate` and `chain reindex` rewrite or destroy the embedded
# node's database, which is a node-state mutation rather than a command the
# browser should be able to drive; the read-only `chain` verbs are allowed
# per subcommand below.
ALLOWED_CHAIN_SUBCOMMANDS = {"info", "blocks", "block", "tx", "verify"}
ALLOWED_WALLET_CMDS = {"wallet"}
# `backup --out`, `sign --out` and `restore --in` write to or read from a
# caller-chosen path (an arbitrary file write / read), and `sign`/`passwd`
# are key-material operations.  None belong on an HTTP surface.  `create` IS
# allowed: the UI needs it to bootstrap a wallet, and because `--path` is
# always forced to the node's own wallet file (below) it can only ever
# create/overwrite that one file, which is what `wallet create` means.
ALLOWED_WALLET_SUBCOMMANDS = {"show", "balance", "addresses", "newaddress",
                              "send", "sweep", "verify", "utxos", "create"}


# ---------------------------------------------------------------------------
# CLI introspection (drives the UI's command palette)
# ---------------------------------------------------------------------------
def cli_tree() -> dict:
    parser = cli_main.build_parser()
    out = {}

    def walk(p, prefix=""):
        node = {"help": p.description or "", "subcommands": {}}
        for name, sub in p._subparsers._group_actions[0].choices.items() \
                if p._subparsers else []:
            child = walk(sub, name)
            opts = []
            for a in sub._actions:
                if a.dest == "help":
                    continue
                opts.append({
                    "name": "--" + a.dest.replace("_", "-"),
                    "help": a.help or "",
                    "choices": list(a.choices) if a.choices else None,
                    "takes_value": bool(getattr(a, "nargs", None) != 0),
                })
            child["options"] = opts
            node["subcommands"][name] = child
        return node

    out = walk(parser)
    out["note"] = ("POST /api/cli with {\"args\": [...]} runs exactly these "
                   "subcommands; POST /api/wallet does the wallet ones with a "
                   "passphrase argument.")
    return out


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------
def serve(host: str = C.DEFAULT_WEB_HOST, port: int = C.DEFAULT_WEB_PORT,
          network: str = "regtest", embedded: Optional[str] = None,
          data_root: Optional[str] = None, allow_remote: bool = False,
          start_node: bool = True, port_offset: int = 0):
    """Start the web suite.  Returns the ThreadingHTTPServer."""
    global NODE, ALLOW_REMOTE
    ALLOW_REMOTE = allow_remote
    if embedded is not None:
        network = "regtest" if embedded == "off" else embedded
        start_node = embedded != "off"
    if not allow_remote and not _is_loopback(host):
        raise SystemExit(
            f"refusing to bind {host}: the web suite exposes full node "
            f"control. Use --host 127.0.0.1, or pass --allow-remote if you "
            f"have a firewall and understand the risk.")
    NODE = NodeManager(network, data_root=data_root, start_node=start_node,
                       port_offset=port_offset)
    httpd = ThreadingHTTPServer((host, port), QeuphHttpHandler)
    httpd.daemon_threads = True
    bar = "=" * 64
    print(bar)
    print(" Qeuph (QUH) node suite")
    print(f" explorer + wallet UI : http://{host}:{port}/")
    print(f" network             : {network}"
          + ("" if start_node else " (read-only, no embedded node)"))
    print(f" ML-DSA-87           : {ml_dsa.backend_name()} backend")
    print(" PoW                 : double SHA3-512, 300 s blocks")
    print(bar)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down...")
    finally:
        if NODE is not None:
            NODE.close()
        httpd.server_close()
    return httpd


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="python -m qeuph.web.server",
        description="Qeuph node explorer, wallet and miner console")
    p.add_argument("--host", default=C.DEFAULT_WEB_HOST)
    p.add_argument("--port", type=int, default=C.DEFAULT_WEB_PORT)
    p.add_argument("--network", default="regtest",
                   choices=["mainnet", "testnet", "regtest"])
    p.add_argument("--embedded-node", default=None,
                   choices=["regtest", "testnet", "mainnet", "off"])
    p.add_argument("--data-root", default=None,
                   help="where the embedded node keeps its chain.db")
    p.add_argument("--allow-remote", action="store_true",
                   help="permit a non-loopback bind (you own the firewall)")
    p.add_argument("--port-offset", type=int, default=0,
                   help="shift the embedded node's P2P/RPC ports, so a second "
                        "web server can run on the same host")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    serve(host=args.host, port=args.port, network=args.network,
          embedded=args.embedded_node, data_root=args.data_root,
          allow_remote=args.allow_remote, port_offset=args.port_offset)


if __name__ == "__main__":
    main()

"""Qeuph Quantum-Resistant Cryptocurrency Web Server & Node Suite (Port 3000).
Serves the full Node Explorer, Quantum Wallet, Miner Controller, and RPC Bridge.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from qeuph import constants as C
from qeuph.config import MAINNET, REGTEST, TESTNET, get_network
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.network.rpc import RPCService
from qeuph.node.node import QNode
from qeuph.services.miner import SoloMiner
from qeuph.wallet import keystore
from qeuph.wallet import mnemonic as mnemonic_mod
from qeuph.wallet.wallet import Wallet

logger = logging.getLogger("qeuph.web")

# Shared Node State
class NodeManager:
    def __init__(self):
        self.lock = threading.RLock()
        self.current_network_name = "regtest"   # Default to regtest for live mining in browser
        self.network = REGTEST
        self.chain: Optional[ChainManager] = None
        self.mempool: Optional[Mempool] = None
        self.node: Optional[QNode] = None
        self.miner: Optional[SoloMiner] = None
        self.wallet: Optional[Wallet] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None
        self.start_time = time.time()
        self.init_node(self.current_network_name)

    def init_node(self, network_name: str):
        with self.lock:
            if self.miner and self.miner.is_mining():
                self.miner.stop()

            self.current_network_name = network_name
            self.network = get_network(network_name)
            
            # Use isolated data dir for web session
            data_dir = f"/tmp/qeuph-web-{network_name}"
            os.makedirs(data_dir, exist_ok=True)
            self.network = get_network(network_name)
            self.network.data_dir = data_dir

            self.chain = ChainManager(self.network, data_dir=data_dir, persist=True)
            self.mempool = Mempool(self.chain.state, fee_rate=C.MIN_RELAY_FEE_RATE, height_fn=self.chain.height)
            self.node = QNode(self.network, self.chain, self.mempool)
            self.miner = SoloMiner(self.node)

            # Persistent / session wallet
            wallet_path = os.path.join(data_dir, "web_wallet.json")
            if os.path.exists(wallet_path):
                try:
                    self.wallet = Wallet.open(wallet_path, None, hrp=self.network.hrp, network=self.network.name)
                except Exception:
                    self.wallet = Wallet.create(hrp=self.network.hrp, network=self.network.name)
                    self.wallet.save(wallet_path, None)
            else:
                self.wallet = Wallet.create(hrp=self.network.hrp, network=self.network.name)
                self.wallet.save(wallet_path, None)

            # Auto-set miner payout to wallet address 0
            addr0 = self.wallet.address_at(0)
            ahash0 = addr_mod.address_to_hash(addr0, self.network.hrp)
            self.miner.set_payout(ahash0)

            # Start event loop thread for async node
            if self._loop and self._loop.is_running():
                # Loop already running
                self.miner.attach_loop(self._loop)
            else:
                self._loop = asyncio.new_event_loop()
                self.miner.attach_loop(self._loop)
                def run_loop():
                    asyncio.set_event_loop(self._loop)
                    self._loop.run_forever()
                self._loop_thread = threading.Thread(target=run_loop, daemon=True, name="qeuph-async")
                self._loop_thread.start()

    def get_status(self) -> dict:
        with self.lock:
            from qeuph.core import pow as pow_mod
            from qeuph.core import reward as reward_mod
            tip = self.chain.tip
            h = tip.height
            wallet_addr = self.wallet.address_at(0)
            ahash = addr_mod.address_to_hash(wallet_addr, self.network.hrp)
            balance = self.chain.state.balance(ahash, h)
            matured_balance = self.chain.state.balance(ahash, h, matured_only=True)
            nonce = self.chain.state.nonce_of(ahash)

            return {
                "network": self.network.name,
                "hrp": self.network.hrp,
                "height": h,
                "best_hash": tip.hash.hex(),
                "difficulty": pow_mod.difficulty_from_bits(tip.header.bits),
                "bits": hex(tip.header.bits),
                "bits_int": tip.header.bits,
                "reward_quphi": self.chain.block_reward(),
                "reward_quh": self.chain.block_reward() / C.QUPHI_PER_QUH,
                "epoch": reward_mod.epoch_at(h),
                "chainwork": hex(self.chain.tip_work),
                "mempool_count": len(self.mempool),
                "mempool_bytes": self.mempool.total_size(),
                "mining": self.miner.is_mining(),
                "hashrate": round(self.miner.hashrate(), 2),
                "blocks_mined": self.miner.blocks_mined,
                "payout_address": self.miner.payout_address_hex,
                "wallet_address": wallet_addr,
                "wallet_balance_quphi": balance,
                "wallet_balance_quh": balance / C.QUPHI_PER_QUH,
                "wallet_matured_quphi": matured_balance,
                "wallet_matured_quh": matured_balance / C.QUPHI_PER_QUH,
                "wallet_nonce": nonce,
                "backend": ml_dsa.backend_name(),
                "uptime": int(time.time() - self.start_time),
            }


NODE = NodeManager()


class QeuphHttpHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # Quiet logging

    def send_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.serve_file("/index.html", "text/html; charset=utf-8")
        elif path == "/api/status":
            self.send_json(NODE.get_status())
        elif path == "/api/blocks":
            self.handle_blocks(parsed.query)
        elif path == "/api/mempool":
            self.handle_mempool()
        elif path.startswith("/api/block/"):
            target = path.replace("/api/block/", "").strip()
            self.handle_single_block(target)
        elif path.startswith("/api/tx/"):
            txid = path.replace("/api/tx/", "").strip()
            self.handle_single_tx(txid)
        elif path == "/api/wallet/info":
            self.handle_wallet_info()
        elif path == "/api/emission":
            from qeuph.core import reward as reward_mod
            rows = reward_mod.emission_table()
            res = [{
                "epoch": e, "start_height": h, "reward_quphi": r,
                "reward_quh": rq, "cumulative_quh": cum / C.QUPHI_PER_QUH
            } for e, h, r, rq, cum in rows]
            self.send_json({
                "cap_quh": C.MAX_SUPPLY_QUH,
                "exact_quphi": reward_mod.exact_total_emission(),
                "exact_quh": reward_mod.exact_total_emission() / C.QUPHI_PER_QUH,
                "table": res
            })
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"

        try:
            data = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            data = {}

        if path == "/api/rpc":
            self.handle_rpc(data)
        elif path == "/api/miner/toggle":
            self.handle_miner_toggle(data)
        elif path == "/api/network/switch":
            net_name = data.get("network", "regtest")
            NODE.init_node(net_name)
            self.send_json({"success": True, "network": net_name, "status": NODE.get_status()})
        elif path == "/api/miner/mine_blocks":
            # Fast mine N blocks on regtest
            n = min(100, max(1, int(data.get("count", 1))))
            with NODE.lock:
                addr = NODE.miner.payout_address_hex or NODE.wallet.address_at(0)
                ahash = addr_mod.address_to_hash(addr, NODE.network.hrp)
                hashes = []
                for _ in range(n):
                    txs = NODE.mempool.best_transactions(2_000_000)
                    b, _ = NODE.chain.create_block_template(ahash, txs)
                    b.mine()
                    NODE.chain.connect_block(b)
                    NODE.mempool.on_new_block(b)
                    hashes.append(b.hash.hex())
            self.send_json({"success": True, "count": len(hashes), "hashes": hashes, "height": NODE.chain.height()})
        elif path == "/api/wallet/send":
            self.handle_wallet_send(data)
        elif path == "/api/wallet/generate":
            phrase = mnemonic_mod.generate_mnemonic()
            w = Wallet.from_mnemonic(phrase, hrp=NODE.network.hrp, network=NODE.network.name)
            self.send_json({
                "mnemonic": phrase,
                "master_seed": w.master_seed.hex(),
                "address_0": w.address_at(0),
                "address_1": w.address_at(1),
            })
        elif path == "/api/wallet/restore":
            phrase = data.get("mnemonic", "").strip()
            try:
                w = Wallet.from_mnemonic(phrase, hrp=NODE.network.hrp, network=NODE.network.name)
                NODE.wallet = w
                addr0 = w.address_at(0)
                NODE.miner.set_payout(addr_mod.address_to_hash(addr0, NODE.network.hrp))
                self.send_json({
                    "success": True,
                    "address_0": addr0,
                    "address_1": w.address_at(1),
                })
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, code=400)
        elif path == "/api/crypto/test_sign":
            # Live FIPS 204 ML-DSA-87 signature test
            msg = data.get("message", "Qeuph Quantum-Resistant Transaction").encode()
            seed, pk, sk = ml_dsa.generate_keypair()
            sig = ml_dsa.sign(sk, msg)
            is_valid = ml_dsa.verify(pk, msg, sig)
            # test tamper
            is_tamper_valid = ml_dsa.verify(pk, msg + b"TAMPERED", sig)
            self.send_json({
                "message": msg.decode(errors="replace"),
                "pk_hex": pk.hex()[:64] + "...",
                "pk_len": len(pk),
                "sk_len": len(sk),
                "sig_hex": sig.hex()[:64] + "...",
                "sig_len": len(sig),
                "verified": is_valid,
                "tamper_detected": not is_tamper_valid,
                "algorithm": "ML-DSA-87 (FIPS 204)",
                "category": "NIST Category 5 (256-bit Post-Quantum Security)"
            })
        else:
            self.send_error(404, "Not Found")

    # ------------------------------------------------------------------
    def handle_blocks(self, query: str):
        params = parse_qs(query)
        limit = min(50, int(params.get("limit", [15])[0]))
        chain = NODE.chain
        h = chain.height()
        blocks = []
        cur_h = h
        while cur_h >= 0 and len(blocks) < limit:
            b = chain.get_block_by_height(cur_h)
            if b:
                d = b.header.to_dict()
                d["tx_count"] = len(b.transactions)
                d["size"] = b.block_size()
                cb = b.transactions[0] if b.transactions else None
                if cb and cb.inputs:
                    d["coinbase_data"] = cb.inputs[0].data.decode(errors="replace")
                blocks.append(d)
            cur_h -= 1
        self.send_json({"blocks": blocks, "total_height": h})

    def handle_single_block(self, target: str):
        chain = NODE.chain
        b = None
        if target.isdigit():
            b = chain.get_block_by_height(int(target))
        else:
            try:
                b = chain.get_block(bytes.fromhex(target))
            except Exception:
                pass
        if not b:
            self.send_json({"error": "Block not found"}, code=404)
            return
        d = b.to_dict(NODE.network.hrp)
        self.send_json(d)

    def handle_mempool(self):
        mp = NODE.mempool
        txs = [t.to_dict(NODE.network.hrp) for t in mp.all_txs()]
        self.send_json({
            "count": len(txs),
            "bytes": mp.total_size(),
            "transactions": txs
        })

    def handle_single_tx(self, txid_hex: str):
        try:
            txid = bytes.fromhex(txid_hex)
        except Exception:
            self.send_json({"error": "Invalid txid"}, code=400)
            return
        # check mempool
        tx = NODE.mempool.get_tx(txid)
        if tx:
            d = tx.to_dict(NODE.network.hrp)
            d["mempool"] = True
            self.send_json(d)
            return
        # check chain
        if NODE.chain.store:
            loc = NODE.chain.store.get_tx_block(txid)
            if loc:
                height, bh = loc
                blk = NODE.chain.get_block(bh)
                for t in (blk.transactions if blk else []):
                    if t.txid() == txid:
                        d = t.to_dict(NODE.network.hrp)
                        d["height"] = height
                        d["block_hash"] = bh.hex()
                        d["confirmations"] = NODE.chain.height() - height + 1
                        self.send_json(d)
                        return
        self.send_json({"error": "Transaction not found"}, code=404)

    def handle_wallet_info(self):
        w = NODE.wallet
        h = NODE.chain.height()
        addrs = []
        for i in range(5):
            addr = w.address_at(i)
            ahash = addr_mod.address_to_hash(addr, NODE.network.hrp)
            bal = NODE.chain.state.balance(ahash, h)
            mbal = NODE.chain.state.balance(ahash, h, matured_only=True)
            nonce = NODE.chain.state.nonce_of(ahash)
            addrs.append({
                "index": i,
                "address": addr,
                "addr_hash": ahash.hex() if ahash else "",
                "balance_quphi": bal,
                "balance_quh": bal / C.QUPHI_PER_QUH,
                "matured_quphi": mbal,
                "matured_quh": mbal / C.QUPHI_PER_QUH,
                "nonce": nonce,
            })
        self.send_json({
            "addresses": addrs,
            "mnemonic": w.to_mnemonic(),
            "master_seed": w.master_seed.hex(),
            "network": NODE.network.name
        })

    def handle_miner_toggle(self, data: dict):
        action = data.get("action", "toggle")
        miner = NODE.miner
        payout = data.get("payout")
        if payout:
            ahash = addr_mod.address_to_hash(payout, NODE.network.hrp)
            if ahash:
                miner.set_payout(ahash)

        if action == "start" or (action == "toggle" and not miner.is_mining()):
            if not miner.payout_address_hex:
                addr0 = NODE.wallet.address_at(0)
                miner.set_payout(addr_mod.address_to_hash(addr0, NODE.network.hrp))
            miner.start()
        else:
            miner.stop()

        self.send_json({"mining": miner.is_mining(), "payout": miner.payout_address_hex})

    def handle_wallet_send(self, data: dict):
        to_addr = data.get("to", "").strip()
        amount_quh = float(data.get("amount", 0))
        fee_quh = float(data.get("fee", 0.01))
        from_idx = int(data.get("from_index", 0))

        if not to_addr or amount_quh <= 0:
            self.send_json({"success": False, "error": "Invalid recipient or amount"}, code=400)
            return

        to_hash = addr_mod.address_to_hash(to_addr, NODE.network.hrp)
        if not to_hash or len(to_hash) != 64:
            self.send_json({"success": False, "error": f"Invalid {NODE.network.hrp} address"}, code=400)
            return

        amount_quphi = round(amount_quh * C.QUPHI_PER_QUH)
        fee_quphi = round(fee_quh * C.QUPHI_PER_QUH)

        with NODE.lock:
            sender_addr = NODE.wallet.address_at(from_idx)
            sender_hash = addr_mod.address_to_hash(sender_addr, NODE.network.hrp)
            
            # Fetch matured UTXOs
            utxos = NODE.chain.state.utxos_for(sender_hash, NODE.chain.height(), matured_only=True)
            total_avail = sum(u.value for _, _, u in utxos)
            if total_avail < amount_quphi + fee_quphi:
                self.send_json({
                    "success": False,
                    "error": f"Insufficient matured funds: have {total_avail / C.QUPHI_PER_QUH:.4f} QUH, need {(amount_quphi + fee_quphi)/C.QUPHI_PER_QUH:.4f} QUH (note 100-block coinbase maturity)"
                }, code=400)
                return

            nonce = NODE.chain.state.nonce_of(sender_hash) + 1
            # Check mempool overlay for pending nonce
            for pending_tx in NODE.mempool.all_txs():
                for inp in pending_tx.inputs:
                    if addr_mod.pk_to_hash(inp.pubkey) == sender_hash:
                        nonce = max(nonce, inp.txnonce + 1)

            # Greedy select UTXOs
            picked = []
            acc = 0
            for txid, idx, u in sorted(utxos, key=lambda x: -x[2].value):
                picked.append((txid, idx, u.value))
                acc += u.value
                if acc >= amount_quphi + fee_quphi:
                    break

            change = acc - amount_quphi - fee_quphi
            outputs = [TxOut(amount_quphi, to_hash)]
            if change > 0:
                outputs.append(TxOut(change, sender_hash))

            key = NODE.wallet.keys.key(from_idx)
            inputs = [TxIn(t, i, nonce) for t, i, _ in picked]
            tx = Transaction(inputs, outputs)
            tx.sign([key.seed] * len(inputs))

            try:
                NODE.mempool.add_tx(tx)
                self.send_json({
                    "success": True,
                    "txid": tx.txid().hex(),
                    "size_bytes": tx.size(),
                    "inputs_count": len(inputs),
                    "outputs_count": len(outputs),
                    "fee_quh": fee_quh,
                    "nonce": nonce,
                    "signature_size": len(inputs[0].signature) if inputs else 0,
                })
            except Exception as e:
                self.send_json({"success": False, "error": f"Mempool rejection: {e}"}, code=400)

    def handle_rpc(self, req: dict):
        method = req.get("method", "")
        params = req.get("params", {}) or {}
        req_id = req.get("id", 1)

        # Build RPC service wrapper on demand
        rpc_svc = RPCService(NODE.node, NODE.miner, "127.0.0.1", NODE.network.rpc_port, lambda: asyncio.Event())
        rpc_svc._loop = NODE._loop

        try:
            res = rpc_svc.dispatch(method, params)
            self.send_json({"jsonrpc": "2.0", "id": req_id, "result": res})
        except Exception as e:
            self.send_json({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}, code=400)

    def serve_file(self, filepath: str, content_type: str):
        if filepath.startswith("/"):
            filepath = filepath[1:]
        try:
            with open(filepath, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_cors()
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(404, f"File Not Found: {e}")

    def send_json(self, data: dict, code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    host = "0.0.0.0"
    port = 3000
    server = ThreadingHTTPServer((host, port), QeuphHttpHandler)
    print(f"================================================================")
    print(f"Qeuph (QUH) Quantum-Resistant Cryptocurrency Suite Running!")
    print(f"Web Dashboard & Node Explorer: http://{host}:{port}/")
    print(f"FIPS 204 ML-DSA-87 + double SHA3-512 Proof-of-Work active.")
    print(f"================================================================")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Qeuph Web Server...")
        if NODE.miner:
            NODE.miner.stop()
        server.server_close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""End-to-end check: THREE CLI/wallet nodes PLUS the web UI node, one mesh.

This is the full-mesh companion to e2e_check.py (which proves two CLI
daemons sync).  Here the mesh is:

    alpha (CLI daemon, miner) <- beta (CLI daemon, --connect alpha)
       ^  ^                        ^
       |  +---- gamma (CLI daemon, dials the WEB node's P2P port)
       |                           (so a CLI node connects INTO the UI node)
       +---- ui node (web suite, --embedded-node regtest --connect alpha)
             (so the UI node dials INTO a CLI node)

Proved, in order:
  1. the web-embedded node joins the P2P mesh in BOTH directions
     (UI -> CLI dial and CLI -> UI dial)
  2. blocks mined on a CLI node reach every other node, including the UI
  3. a payment made from the UI's Send route is seen by the CLI nodes
  4. a payment made through the CLI wallet is seen by the UI
  5. after mining, the payment confirms everywhere and all four tips agree
  6. a SECOND web instance in remote-attach mode (--embedded-node off
     --remote-rpc <alpha RPC>) serves the same chain and can submit a
     signed payment to the remote node
  7. with --network testnet, the same mesh forms on the testnet profile

Run:  python3 tools/e2e_three_nodes.py [--skip-testnet]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from qeuph import constants as C                      # noqa: E402
from qeuph.crypto import address as addr_mod          # noqa: E402
from qeuph.crypto import ml_dsa                       # noqa: E402


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_json(url, path, body=None, timeout=60):
    if body is None:
        with urllib.request.urlopen(url + path, timeout=timeout) as r:
            return json.loads(r.read())
    req = urllib.request.Request(
        url + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def rpc(url, method, params=None, timeout=120):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        doc = json.loads(r.read())
    if doc.get("error"):
        raise RuntimeError(f"{method}: {doc['error']}")
    return doc["result"]


def wait_for(fn, timeout=90.0, what="condition", interval=0.4):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:                    # noqa: BLE001
            last = e
        time.sleep(interval)
    raise SystemExit(f"timed out waiting for {what} (last={last!r})")


def cli(*args, expect=0, timeout=300):
    p = subprocess.run([sys.executable, "-m", "qeuph.cli.main", *args],
                       cwd=ROOT, capture_output=True, text=True,
                       timeout=timeout)
    if expect is not None and p.returncode != expect:
        raise SystemExit(f"qeuph {' '.join(args)} -> {p.returncode}\n"
                         f"{p.stdout}\n{p.stderr}")
    return p.stdout


def make_address(hrp):
    seed, pk, _ = ml_dsa.generate_keypair()
    return addr_mod.hash_to_address(addr_mod.pk_to_hash(pk), hrp)


class Daemon:
    """A `qeuph node` subprocess (a CLI-driven node)."""

    def __init__(self, root, name, network="regtest", connect=None,
                 p2p_host="127.0.0.1"):
        self.name = name
        self.network = network
        self.p2p = free_port()
        self.rpc_port = free_port()
        self.url = f"http://127.0.0.1:{self.rpc_port}/"
        # per-NETWORK directory: a data dir holds exactly one chain, so two
        # profiles must never share one
        self.dir = os.path.join(root, network, name)
        argv = [sys.executable, "-m", "qeuph.cli.main", "node",
                "--network", network, "--data-dir", self.dir,
                "--p2p-port", str(self.p2p), "--rpc-port", str(self.rpc_port),
                "--p2p-host", p2p_host]
        if connect:
            argv += ["--connect", connect]
        self.log_path = os.path.join(root, f"{name}.log")
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(argv, cwd=ROOT, stdout=self.log,
                                     stderr=subprocess.STDOUT)

    def height(self):
        return rpc(self.url, "getblockcount")

    def wait_ready(self, timeout=45):
        def ok():
            if self.proc.poll() is not None:
                raise SystemExit(f"{self.name} died:\n"
                                 f"{open(self.log_path).read()[-2000:]}")
            try:
                self.height()
                return True
            except Exception:
                return False
        wait_for(ok, timeout=timeout, what=f"{self.name} RPC up")

    def stop(self):
        try:
            rpc(self.url, "stop", timeout=10)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


class WebNode:
    """A `python -m qeuph.web.server` subprocess (the UI-driven node)."""

    def __init__(self, root, name, network="regtest", connect=None,
                 remote_rpc=None, port_offset=None):
        self.name = name
        self.network = network
        self.http_port = free_port()
        self.url = f"http://127.0.0.1:{self.http_port}"
        self.dir = os.path.join(root, name)
        if port_offset is None:
            port_offset = self._pick_offset(network)
        self.port_offset = port_offset
        argv = [sys.executable, "-m", "qeuph.web.server",
                "--host", "127.0.0.1", "--port", str(self.http_port),
                "--network", network, "--data-root", self.dir,
                "--p2p-host", "127.0.0.1"]
        argv += (["--embedded-node", "off", "--remote-rpc", remote_rpc]
                 if remote_rpc else
                 ["--embedded-node", network])
        if connect:
            for c in connect:
                argv += ["--connect", c]
        if not remote_rpc:
            argv += ["--port-offset", str(port_offset)]
        self.log_path = os.path.join(root, f"{name}.log")
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(argv, cwd=ROOT, stdout=self.log,
                                     stderr=subprocess.STDOUT)

    @staticmethod
    def _pick_offset(network):
        """A port offset whose derived P2P and RPC ports are actually free.

        The embedded node derives its ports from the network profile
        (base + 1000/2000, then + offset).  Claiming a port from the OS and
        working the offset back from it is the robust way to do that - but
        Windows hands out high ephemeral ports (49k+), so the derived offset
        can land far above the 1..20000 window this used to require.  Every
        attempt then "failed" on a perfectly healthy host and the testnet
        section of this check aborted before it ran.  Both derived ports are
        now verified with the same socket options the node itself binds with.
        """
        from qeuph.network.listen import listener_socket
        base = {"mainnet": 0, "testnet": 1000, "regtest": 2000}[network]
        base_port = {"mainnet": C.DEFAULT_P2P_PORT,
                     "testnet": 29090, "regtest": 39090}[network]
        rpc_base = base_port + 1

        def free(p):
            try:
                listener_socket("127.0.0.1", p).close()
                return True
            except OSError:
                return False

        for _ in range(64):
            p2p = free_port()
            offset = p2p - base_port - base
            if not (1 <= offset <= 60000):
                continue
            if free(p2p) and free(rpc_base + offset):
                return offset
        raise SystemExit("could not pick a free embedded P2P port")

    def api(self, path, body=None, timeout=90):
        return http_json(self.url, path, body, timeout=timeout)

    def wait_ready(self, timeout=60):
        wait_for(lambda: (self.proc.poll() is None
                          and self._booted()) or None,
                 timeout=timeout, what=f"{self.name} web up")

    def _booted(self):
        try:
            st = self.api("/api/status", timeout=5)
            return bool(st.get("network"))
        except Exception:
            return False

    def status(self):
        return self.api("/api/status")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


def stage(title):
    print(f"\n{title}")
    print("-" * (len(title) + 1))


def run_mesh(root, network, skip_remote=False):
    """The full UI<->CLI mesh check on one network profile."""
    hrp = {"regtest": "rquh", "testnet": "tquh"}[network]
    nodes = []

    def stop_all():
        for d in nodes:
            try:
                d.stop()
            except Exception:
                pass

    try:
        stage(f"[mesh:{network}] boot 3 CLI daemons + the web UI node")
        alpha = Daemon(root, "alpha", network=network)
        nodes.append(alpha)
        alpha.wait_ready()

        ui = WebNode(root, "ui", network=network,
                     connect=[f"127.0.0.1:{alpha.p2p}"])
        nodes.append(ui)
        ui.wait_ready()
        beta = Daemon(root, "beta", network=network,
                      connect=f"127.0.0.1:{alpha.p2p}")
        nodes.append(beta)
        beta.wait_ready()
        # gamma dials the UI node's P2P port: CLI -> UI direction
        ui_p2p = ui.status().get("p2p_port")
        assert ui_p2p, "UI status did not report its P2P port"
        gamma = Daemon(root, "gamma", network=network,
                       connect=f"127.0.0.1:{ui_p2p}")
        nodes.append(gamma)
        gamma.wait_ready()

        stage(f"[mesh:{network}] 1. P2P mesh forms in BOTH directions")
        wait_for(lambda: ui.status()["peers"] >= 1,
                 what="UI node gained peers (UI -> CLI dial works)")
        wait_for(lambda: rpc(alpha.url, "getconnectioncount") >= 1,
                 what="alpha sees the UI node (inbound)")
        wait_for(lambda: rpc(gamma.url, "getconnectioncount") >= 1,
                 what="gamma connected (CLI -> UI dial works)")
        wait_for(lambda: ui.status()["peers"] >= 2,
                 what="UI node accepts gamma's inbound dial")
        print(f"    alpha peers={rpc(alpha.url, 'getconnectioncount')} "
              f"beta peers={rpc(beta.url, 'getconnectioncount')} "
              f"gamma peers={rpc(gamma.url, 'getconnectioncount')} "
              f"ui peers={ui.status()['peers']}")

        stage(f"[mesh:{network}] 2. blocks mined on a CLI node reach ALL nodes")
        payout = make_address(hrp)
        rpc(alpha.url, "generate", {"nblocks": 6, "address": payout})
        wait_for(lambda: ui.status()["height"] == 6,
                 what="UI node synced to height 6")
        for name, d in (("beta", beta), ("gamma", gamma)):
            wait_for(lambda d=d: d.height() == 6, what=f"{name} synced to 6")
        print(f"    heights alpha={alpha.height()} beta={beta.height()} "
              f"gamma={gamma.height()} ui={ui.status()['height']}")

        stage(f"[mesh:{network}] 3. payment from the UI -> CLI nodes see it")
        # fund a UI wallet: mine 105 matured blocks to the wallet's addr #0
        wcreate = ui.api("/api/wallet", {"args": ["wallet", "create",
                                                  "--unencrypted"]})
        assert wcreate["ok"], wcreate
        addrs = ui.api("/api/wallet/addresses?count=2")["addresses"]
        assert len(addrs) >= 2
        ui.api("/api/miner/payout", {"address": addrs[0]["address"]})
        gen = ui.api("/api/generate", {"count": 105})
        assert gen.get("ok"), gen
        target = 6 + 105
        for name, obj in (("alpha", alpha), ("beta", beta), ("gamma", gamma)):
            wait_for(lambda o=obj: o.height() == target,
                     what=f"{name} synced to {target}")
        wait_for(lambda: ui.status()["height"] == target, what="ui synced")
        # a CLI-side recipient
        recv = make_address(hrp)
        sent = ui.api("/api/wallet/send", {
            "to": recv, "amount": "3.25", "fee": "0.01", "from_index": 0,
            "passphrase": ""})
        assert sent.get("success"), sent
        txid = sent["txid"]
        print(f"    UI send txid={txid[:24]}... "
              f"({sent['size_bytes']} B, nonce {sent['nonce']})")
        wait_for(lambda: txid in rpc(beta.url, "getmempool")["txids"],
                 what="beta's mempool holds the UI payment")
        wait_for(lambda: txid in rpc(gamma.url, "getmempool")["txids"],
                 what="gamma's mempool holds the UI payment")

        stage(f"[mesh:{network}] 4. payment from a CLI wallet -> UI sees it")
        cli("wallet", "create", "--unencrypted", "--network", network,
            "--path", os.path.join(root, "cliwallet.json"))
        # fund the CLI wallet by mining to its address #0 through alpha's
        # RPC (a second process writing the same chain.db would be invisible)
        cli_addr = cli("wallet", "address", "--index", "0", "--network",
                       network, "--passphrase", "",
                       "--path", os.path.join(root, "cliwallet.json")).strip()
        rpc(alpha.url, "generate", {"nblocks": 105, "address": cli_addr})
        target2 = target + 105
        for name, obj in (("beta", beta), ("gamma", gamma)):
            wait_for(lambda o=obj: o.height() == target2,
                     what=f"{name} synced to {target2}")
        wait_for(lambda: ui.status()["height"] == target2, what="ui synced")
        ui_recv = addrs[1]["address"]
        out = cli("wallet", "send", "--to", ui_recv, "--amount", "1.75",
                  "--fee", "0.01", "--network", network,
                  "--passphrase", "",
                  "--path", os.path.join(root, "cliwallet.json"),
                  "--rpc", alpha.url)
        m = re.search(r"txid\s+([0-9a-f]{128})", out)  # SHA3-512 hex
        assert m, f"no txid in wallet send output:\n{out}"
        cli_txid = m.group(1)
        print(f"    CLI send txid={cli_txid[:24]}...")
        wait_for(lambda: cli_txid in
                 [t["txid"] for t in ui.api("/api/mempool")["transactions"]],
                 what="UI mempool view shows the CLI payment")

        stage(f"[mesh:{network}] 5. confirmation + 4-way tip agreement")
        rpc(alpha.url, "generate", {"nblocks": 1, "address": payout})
        target3 = target2 + 1
        for name, obj in (("alpha", alpha), ("beta", beta), ("gamma", gamma)):
            wait_for(lambda o=obj: o.height() == target3,
                     what=f"{name} at {target3}")
        wait_for(lambda: ui.status()["height"] == target3, what="ui at target")
        detail = ui.api(f"/api/tx/{txid}")
        assert detail.get("height"), f"UI tx never confirmed: {detail}"
        tips = {
            "alpha": rpc(alpha.url, "getbestblockhash"),
            "beta": rpc(beta.url, "getbestblockhash"),
            "gamma": rpc(gamma.url, "getbestblockhash"),
            "ui": ui.status()["best_hash"],
        }
        assert len(set(tips.values())) == 1, f"tips disagree: {tips}"
        print(f"    all four tips agree at height {target3}: "
              f"{tips['alpha'][:24]}...")

        if not skip_remote:
            stage(f"[mesh:{network}] 6. remote-attach UI on alpha's RPC")
            # share the UI node's funded wallet with the remote instance:
            # the keystore stays local to whichever UI you use; only signed
            # transactions ever cross to the remote node
            ui_wallet = os.path.join(ui.dir, network, "wallet.json")
            ui2_wallet_dir = os.path.join(root, "ui-remote", network)
            os.makedirs(ui2_wallet_dir, exist_ok=True)
            shutil.copy(ui_wallet, os.path.join(ui2_wallet_dir, "wallet.json"))
            ui2 = WebNode(root, "ui-remote", network=network,
                          remote_rpc=alpha.url)
            nodes.append(ui2)
            ui2.wait_ready()
            st = ui2.status()
            assert st["mode"] == "remote" and st["remote_rpc"] == alpha.url, st
            assert st["height"] == target3
            blocks = ui2.api("/api/blocks?limit=5")
            assert blocks["total_height"] == target3
            rres = ui2.api("/api/rpc", {"method": "getblockcount"})
            assert rres["result"] == target3
            # remote wallet send: signs locally, broadcasts to alpha
            rsent = ui2.api("/api/wallet/send", {
                "to": recv, "amount": "0.5", "fee": "0.01", "from_index": 0,
                "passphrase": ""})
            assert rsent.get("success"), rsent
            wait_for(lambda: rsent["txid"] in
                     rpc(alpha.url, "getmempool")["txids"],
                     what="remote-UI payment lands in alpha's mempool")
            print(f"    remote UI height={st['height']} "
                  f"relay txid={rsent['txid'][:24]}...")

        print(f"\n[mesh:{network}] ALL CHECKS PASSED")
    finally:
        stop_all()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-testnet", action="store_true",
                    help="only run the regtest mesh")
    args = ap.parse_args()

    root = tempfile.mkdtemp(prefix="qeuph-3node-")
    print(f"workspace {root}")
    try:
        run_mesh(root, "regtest")
        if not args.skip_testnet:
            run_mesh(root, "testnet")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    print("\nE2E COMPLETE: 3-node CLI mesh + web UI node, both directions, "
          "regtest + testnet")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""End-to-end developer check: real daemons, real P2P sync, real CLI.

Boots two regtest daemons, syncs a chain between them over the P2P network,
mines, sends a transaction through the CLI, and verifies everything. Run it
after any change that touches consensus, networking or the wallet.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from qeuph import constants as C
from qeuph.wallet import Wallet


def free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rpc(url, method, params=None, timeout=60):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        doc = json.loads(r.read())
    if doc.get("error"):
        raise RuntimeError(f"{method}: {doc['error']}")
    return doc["result"]


def cli(*args, expect=0, timeout=300):
    p = subprocess.run([sys.executable, "-m", "qeuph.cli.main", *args],
                       cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if expect is not None and p.returncode != expect:
        raise SystemExit(f"qeuph {' '.join(args)} -> {p.returncode}\n"
                         f"{p.stdout}\n{p.stderr}")
    return p.stdout


class Daemon:
    def __init__(self, name, root, connect=None, wallet_path=None):
        self.name = name
        self.p2p = free_port()
        self.rpc_port = free_port()
        self.url = f"http://127.0.0.1:{self.rpc_port}/"
        self.dir = os.path.join(root, name)
        self.wallet_path = wallet_path
        argv = [sys.executable, "-m", "qeuph.cli.main", "node",
                "--network", "regtest", "--data-dir", self.dir,
                "--p2p-port", str(self.p2p), "--rpc-port", str(self.rpc_port)]
        if connect:
            argv += ["--connect", connect]
        self.log = open(os.path.join(root, f"{name}.log"), "w")
        self.proc = subprocess.Popen(argv, cwd=ROOT, stdout=self.log,
                                    stderr=subprocess.STDOUT)

    def wait_ready(self, timeout=30):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise SystemExit(f"{self.name} died:\n"
                                 f"{open(self.log.name).read()[-2000:]}")
            try:
                rpc(self.url, "getblockcount", timeout=2)
                return
            except Exception:
                time.sleep(0.15)
        raise SystemExit(f"{self.name} RPC never came up")

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


def generate(url, address, n):
    """Mine through the running node's RPC.

    A running daemon owns its data directory: a second process writing to the
    same chain.db is invisible to the first one, because SQLite is not a
    notification channel.  Always drive blocks through the node itself.
    """
    got = rpc(url, "generate", {"nblocks": n, "address": address}, timeout=600)
    return got["hashes"]


def main():
    root = tempfile.mkdtemp(prefix="qeuph-e2e-")
    print(f"workspace {root}")
    try:
        # ---------------------------------------------------------- 1
        print("\n[1] mainnet genesis identity")
        out = cli("genesis")
        g = json.loads(out)
        assert g["matches_pinned"] and g["valid"] and g["meets_target"]
        assert g["hash"] == C.CHECKPOINTS[0].hex()
        print(f"    {g['hash']}")

        # ---------------------------------------------------------- 2
        print("\n[2] emission schedule")
        out = cli("emission", "--json")
        rows = json.loads(out)
        assert len(rows) == 54
        assert abs(rows[-1]["reward_quh"] - 1e-8) < 1e-16
        print(f"    54 epochs, exact {C.MAX_SUPPLY - 3_149_999_985_930_000:,} "
              f"quphi below the cap")

        # ---------------------------------------------------------- 3
        print("\n[3] two regtest daemons, P2P sync")
        da = Daemon("alpha", root)
        db = Daemon("beta", root, connect=f"127.0.0.1:{da.p2p}")
        try:
            da.wait_ready()
            db.wait_ready()

            w = Wallet.create(hrp="rquh", network="regtest")
            addr0 = w.address_at(0)
            generate(da.url, addr0, 12)
            print("    alpha mined 12 blocks")

            for _ in range(300):
                if rpc(db.url, "getblockcount") == 12:
                    break
                time.sleep(0.1)
            hb = rpc(db.url, "getblockcount")
            assert hb == 12, f"beta synced to {hb}, expected 12"
            best_a = rpc(da.url, "getblockchaininfo")["best"]
            best_b = rpc(db.url, "getblockchaininfo")["best"]
            assert best_a == best_b
            bal = rpc(db.url, "getbalance",
                      {"address": w.address_at(0)})["balance"]
            assert bal == 12 * 50 * C.QUPHI_PER_QUH, bal
            print(f"    beta synced to height {hb}, balances match "
                  f"({bal / C.QUPHI_PER_QUH:.0f} QUH)")

            peers = rpc(db.url, "getpeerinfo")
            assert peers["count"] >= 1
            print(f"    beta sees {peers['count']} peer(s)")

            # ------------------------------------------------------ 4
            print("\n[4] wallet on disk, funds mined to maturity")
            wp = os.path.join(root, "wallet.json")
            w.save(wp, "")
            rcli = ["--path", wp, "--network", "regtest", "--passphrase", ""]
            on_disk = cli("wallet", "address", *rcli, "--index", "0").strip()
            assert on_disk == addr0, "the wallet on disk must match"
            # a further 101 blocks so the first coinbase matures
            generate(da.url, addr0, 101)
            for _ in range(600):
                if rpc(db.url, "getblockcount") >= 113:
                    break
                time.sleep(0.1)
            assert rpc(db.url, "getblockcount") >= 113

            bal = rpc(da.url, "getbalance", {"address": addr0})
            print(f"    balance {bal['balance_quh']:.0f} QUH, spendable "
                  f"{bal['matured_balance_quh']:.0f} QUH")
            assert bal["matured_balance_quh"] > 0

            # ------------------------------------------------------ 5
            print("\n[5] send through the CLI, confirm on both nodes")
            w2 = Wallet.create(hrp="rquh", network="regtest")
            dest = w2.address_at(0)
            out = cli("wallet", "send", *rcli, "--to", dest,
                      "--amount", "12.5", "--fee", "0.01", "--rpc", da.url)
            txid = [l.split()[-1] for l in out.splitlines()
                    if l.startswith("txid")][0]
            print(f"    sent 12.5 QUH, txid {txid[:32]}…")
            assert rpc(da.url, "getrawmempool") == [txid]

            # one more block on alpha picks the pending transaction up
            generate(da.url, addr0, 1)
            for _ in range(600):
                if rpc(db.url, "getrawmempool") == []:
                    break
                time.sleep(0.1)
            assert rpc(db.url, "getrawmempool") == [], \
                "beta did not confirm the transaction"
            for url, label in ((da.url, "alpha"), (db.url, "beta")):
                got = rpc(url, "getbalance", {"address": dest})
                assert got["balance"] == round(12.5 * C.QUPHI_PER_QUH), \
                    (label, got)
            print("    confirmed on both nodes; recipient balance 12.5 QUH")

            info = rpc(db.url, "gettransaction", {"txid": txid})
            assert info["confirmations"] >= 1
            print(f"    confirmed with {info['confirmations']} confirmation(s)")

            # ------------------------------------------------------ 6
            print("\n[6] offline chain inspection and reindex")
            out = cli("chain", "info", "--network", "regtest",
                      "--data-dir", da.dir, "--json")
            info = json.loads(out)
            assert info["height"] == rpc(da.url, "getblockcount")
            print(f"    offline height {info['height']}, tip {info['tip'][:24]}…")
            out = cli("chain", "verify", "--network", "regtest",
                      "--data-dir", da.dir, "--json")
            rep = json.loads(out)
            assert rep["ok"], rep
            print(f"    re-validated {rep['checked']} blocks")
            out = cli("chain", "reindex", "--network", "regtest",
                      "--data-dir", da.dir, "--json")
            rep = json.loads(out)
            assert rep["tip"] == info["height"]
            print(f"    reindexed {rep['blocks']} blocks, tip {rep['tip']}")

            # ------------------------------------------------------ 7
            print("\n[7] RPC auth")
            rport = free_port()
            argv = [sys.executable, "-m", "qeuph.cli.main", "node",
                    "--network", "regtest", "--data-dir",
                    os.path.join(root, "secure"),
                    "--p2p-port", str(free_port()),
                    "--rpc-port", str(rport),
                    "--rpc-user", "op", "--rpc-password", "hunter2"]
            log = open(os.path.join(root, "secure.log"), "w")
            proc = subprocess.Popen(argv, cwd=ROOT, stdout=log,
                                    stderr=subprocess.STDOUT)
            url = f"http://127.0.0.1:{rport}/"
            try:
                ok = False
                end = time.time() + 30
                while time.time() < end:
                    try:
                        req = urllib.request.Request(
                            url, data=json.dumps(
                                {"jsonrpc": "2.0", "id": 1,
                                 "method": "getblockcount"}).encode(),
                            headers={"Content-Type": "application/json"})
                        urllib.request.urlopen(req, timeout=3)
                        break
                    except urllib.error.HTTPError as e:
                        if e.code == 401:
                            ok = True
                            break
                    except Exception:
                        pass
                    time.sleep(0.15)
                assert ok, "an unauthenticated RPC call was not refused"
                import base64
                cred = base64.b64encode(b"op:hunter2").decode()
                req = urllib.request.Request(
                    url, data=json.dumps(
                        {"jsonrpc": "2.0", "id": 1,
                         "method": "getblockcount"}).encode(),
                    headers={"Content-Type": "application/json",
                             "Authorization": "Basic " + cred})
                with urllib.request.urlopen(req, timeout=10) as r:
                    assert json.loads(r.read())["result"] == 0
                print("    unauthenticated refused (401), authenticated "
                      "accepted")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                log.close()
        finally:
            da.stop()
            db.stop()

        print("\nALL END-TO-END CHECKS PASSED")
        return 0
    finally:
        if not os.environ.get("KEEP"):
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

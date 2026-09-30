#!/usr/bin/env python3
"""Boot a real daemon on each network and verify it end to end.

`e2e_check.py` exercises regtest with two daemons and a wallet; this script
covers the part that is easy to leave untested - the OTHER networks.  For
each of mainnet / testnet / regtest it:

  * starts a real `qeuph node` on free ports and a throwaway data directory
  * waits for the JSON-RPC port and checks the chain identity the node
    actually serves (genesis hash, height 0, network name, HRP)
  * checks the RPC surface an operator depends on (getblockchaininfo,
    getrewardinfo, getnetworkinfo, getnodeinfo, the address methods)
  * mines a few blocks where the difficulty allows it (regtest and testnet;
    mainnet is never mined) and re-checks the tip and the payouts
  * on mainnet, checks the two things that only mainnet can show: the
    start-up preflight warnings, and that solo mining is refused
  * stops the node through the RPC `stop` method and requires a clean exit

    python3 tools/network_check.py                  # all three networks
    python3 tools/network_check.py --network=testnet
    python3 tools/network_check.py --json
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

from qeuph import constants as C                    # noqa: E402
from qeuph.config import NETWORKS, get_network      # noqa: E402
from qeuph.core import genesis as genesis_mod       # noqa: E402
from qeuph.crypto import address as addr_mod        # noqa: E402
from qeuph.crypto import ml_dsa                     # noqa: E402

MINABLE = {"regtest", "testnet"}       # mainnet PoW is not a test


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def rpc(url, method, params=None, timeout=180):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params or {}}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            doc = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method}: HTTP {e.code}") from e
    if doc.get("error"):
        raise RuntimeError(f"{method}: {doc['error']}")
    return doc["result"]


class Daemon:
    def __init__(self, name, root):
        self.name = name
        self.p2p = free_port()
        self.rpc_port = free_port()
        self.url = f"http://127.0.0.1:{self.rpc_port}/"
        self.dir = os.path.join(root, name)
        self.log_path = os.path.join(root, f"{name}.log")
        self.log = open(self.log_path, "w", encoding="utf-8")
        argv = [sys.executable, "-m", "qeuph.cli.main", "node",
                "--network", name, "--data-dir", self.dir,
                "--p2p-port", str(self.p2p),
                "--rpc-port", str(self.rpc_port)]
        self.proc = subprocess.Popen(argv, cwd=ROOT, stdout=self.log,
                                     stderr=subprocess.STDOUT)

    def log_tail(self, n=3000):
        try:
            with open(self.log_path, encoding="utf-8", errors="replace") as f:
                return f.read()[-n:]
        except OSError:
            return ""

    def wait_ready(self, timeout=90):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise SystemExit(f"{self.name} died:\n{self.log_tail()}")
            try:
                rpc(self.url, "getblockcount", timeout=5)
                return
            except Exception:
                time.sleep(0.15)
        raise SystemExit(f"{self.name} RPC never came up:\n{self.log_tail()}")

    def stop(self):
        try:
            rpc(self.url, "stop", timeout=15)
        except Exception:
            pass
        try:
            code = self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = self.proc.wait(timeout=10)
        self.log.close()
        return code


def check(name, ok, detail, results):
    ok = bool(ok)
    results.append({"check": name, "ok": ok, "detail": detail})
    print(f"  {'ok  ' if ok else 'FAIL'} {name:<34} {detail}")
def run_network(name, root, results):
    print(f"\n[{name}] {ROOT}")
    net = get_network(name)
    d = Daemon(name, root)
    try:
        d.wait_ready()

        genesis = genesis_mod.build_genesis(net)
        height = rpc(d.url, "getblockcount")
        check("chain identity",
              height == 0 and
              rpc(d.url, "getbestblockhash") == genesis.hash.hex(),
              f"height {height}, genesis {genesis.hash.hex()[:16]}...",
              results)

        info = rpc(d.url, "getblockchaininfo")
        check("getblockchaininfo",
              info.get("chain") == name and info.get("blocks") == 0 and
              info.get("headers") == 0,
              f"chain={info.get('chain')} blocks={info.get('blocks')} "
              f"bits={info.get('bits')}", results)

        reward = rpc(d.url, "getrewardinfo", {"height": 0})
        check("getrewardinfo",
              reward.get("reward") == C.REWARD_INITIAL and
              reward.get("cap") == C.MAX_SUPPLY,
              f"reward {reward.get('reward')} quphi, cap {reward.get('cap')}",
              results)

        netinfo = rpc(d.url, "getnetworkinfo")
        check("getnetworkinfo", netinfo.get("network") == name,
              f"network={netinfo.get('network')} "
              f"magic={netinfo.get('magic')!r}", results)
        check("getnodeinfo", "uptime" in rpc(d.url, "getnodeinfo"),
              f"uptime={rpc(d.url, 'uptime')}s", results)

        seed, pk, _ = ml_dsa.generate_keypair()
        addr = addr_mod.pk_to_address(pk, net.hrp)
        valid = rpc(d.url, "validateaddress", {"address": addr})
        check("address methods",
              valid.get("isvalid") and valid.get("address") == addr and
              addr.startswith(net.hrp + "1"),
              f"{addr[:14]}... ({len(addr)} chars, hrp {net.hrp})", results)
        check("a fresh address is empty",
              rpc(d.url, "getbalance", {"address": addr})["balance"] == 0,
              "0 quphi", results)
        check("a mainnet address is refused here" if name != "mainnet"
              else "a regtest address is refused here",
              _foreign_address_rejected(d.url, net), "HRP binding enforced",
              results)

        if name in MINABLE:
            got = rpc(d.url, "generate", {"nblocks": 3, "address": addr})
            height = rpc(d.url, "getblockcount")
            check("mining", height == 3 and len(got["hashes"]) == 3,
                  f"height {height} on {name}, "
                  f"{len(got['hashes'])} block hashes", results)
            check("payouts reached the miner",
                  rpc(d.url, "getbalance",
                      {"address": addr})["balance"] == 3 * C.REWARD_INITIAL,
                  f"{3 * C.REWARD_INITIAL} quphi", results)
            check("mempool starts empty",
                  rpc(d.url, "getmempoolinfo")["count"] == 0,
                  "0 pending transactions", results)
            check("block lookups agree",
                  rpc(d.url, "getblock", {"hash": 2, "verbose": True})["hash"]
                  == rpc(d.url, "getblockhash", {"height": 2}) ==
                  got["hashes"][1],
                  "getblock/getblockhash/generate agree", results)
        else:
            log = d.log_tail(6000)
            check("preflight ran at start-up", "preflight" in log,
                  "startup warnings logged", results)
            check("no peers is reported, not hidden",
                  "bootstrap" in log or "DNS" in log,
                  "it says it cannot find the network on its own", results)
            try:
                rpc(d.url, "startminer", {"address": addr})
                check("mainnet solo mining refused", False,
                      "startminer was accepted on mainnet", results)
            except RuntimeError as e:
                check("mainnet solo mining refused",
                      "mainnet" in str(e).lower(), str(e)[:64], results)
        return addr
    finally:
        code = d.stop()
        check(f"{name} stops cleanly through the RPC", code == 0,
              f"exit code {code}", results)


def _foreign_address_rejected(url, net) -> bool:
    """A valid address of a DIFFERENT network must not validate here."""
    other = "mainnet" if not net.is_mainnet else "regtest"
    h = ml_dsa.generate_keypair()[1]
    foreign = addr_mod.pk_to_address(h, get_network(other).hrp)
    try:
        return rpc(url, "validateaddress", {"address": foreign})["isvalid"] \
            is False
    except RuntimeError:
        return True


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    if as_json:
        argv.remove("--json")
    names = [a.split("=", 1)[1] for a in argv if a.startswith("--network=")]
    names += [a for a in argv if not a.startswith("-")]
    names = names or list(NETWORKS)
    for n in names:
        if n not in NETWORKS:
            raise SystemExit(f"unknown network {n!r}")

    results = []
    root = tempfile.mkdtemp(prefix="qeuph-network-check-")
    try:
        for name in names:
            run_network(name, root, results)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    failed = [r for r in results if not r["ok"]]
    if as_json:
        print(json.dumps({"checks": results, "ok": not failed}, indent=2))
    print()
    if failed:
        print(f"{len(results) - len(failed)} ok, {len(failed)} FAILED")
        for r in failed:
            print(f"  FAILED {r['check']}: {r['detail']}")
        return 1
    print(f"all {len(results)} checks passed ({', '.join(names)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())


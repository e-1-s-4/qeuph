#!/usr/bin/env python3
"""Ad-hoc end-to-end check of the web suite (developer helper)."""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

PORT = int(os.environ.get("WEBPORT", "3222"))
BASE = f"http://127.0.0.1:{PORT}"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get(path, timeout=30):
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return json.loads(r.read())


def post(path, body, timeout=180):
    req = urllib.request.Request(BASE + path,
                                 data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def main():
    data_root = "/tmp/qeuph-webtest"
    shutil.rmtree(data_root, ignore_errors=True)
    env = dict(os.environ, TMPDIR=data_root, PYTHONPATH=ROOT)
    proc = subprocess.Popen(
        [sys.executable, "-m", "qeuph.web.server", "--port", str(PORT),
         "--data-root", data_root, "--port-offset", "12000"],
        cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(200):
            try:
                get("/api/status", timeout=2)
                break
            except Exception:
                time.sleep(0.1)
        else:
            print(proc.stdout.read())
            raise SystemExit("server did not start")

        st = get("/api/status")
        print("status        ", st["network"], "height", st["height"],
              "rpc", st["rpc_url"])
        assert st["network"] == "regtest"

        print("cli tree      ", sorted(get("/api/cli")["subcommands"]))
        print("crypto        ", get("/api/crypto")["signature_scheme"])

        r = post("/api/wallet", {"args": ["wallet", "create", "--unencrypted"]})
        print("wallet create ", r["ok"])
        assert r["ok"], r
        out = r["stdout"]
        assert "redacted" in out, "the recovery phrase must never be returned"
        addr0 = [ln for ln in out.splitlines() if "address 0" in ln][0]
        print("   ", addr0.strip())
        addr = addr0.split()[-1]

        addrs = get("/api/wallet/addresses")
        assert addrs["exists"] and addrs["addresses"], addrs
        print("addresses     ", addrs["addresses"][0]["address"][:24], "...")

        r = post("/api/wallet", {"args": ["wallet", "mnemonic"]})
        print("mnemonic      ", "blocked" if not r["ok"] else "LEAKED!")
        assert not r["ok"], "mnemonic must be refused over HTTP"

        # mine 101 blocks, then send
        r = post("/api/generate", {"count": 101, "address": addr}, timeout=300)
        print("generate 101  ", r["ok"], "height", r["height"])
        bal = post("/api/rpc", {"method": "getbalance", "params":
                                {"address": addr}})["result"]
        print("balance       ", bal["balance_quh"], "QUH, spendable",
              bal["matured_balance_quh"])

        r = post("/api/wallet", {
            "args": ["wallet", "send", "--to", addr, "--amount", "10",
                     "--fee", "0.01"],
            "passphrase": ""})
        print("wallet send   ", r["ok"], r.get("error", ""))
        print(r.get("stdout", "")[:400])
        assert r["ok"], r

        mem = get("/api/mempool")
        print("mempool       ", mem["count"], "tx")
        assert mem["count"] == 1

        post("/api/generate", {"count": 1, "address": addr}, timeout=120)
        assert get("/api/mempool")["count"] == 0, "tx not confirmed"

        blocks = get("/api/blocks?limit=3")
        print("blocks        ", [b["height"] for b in blocks["blocks"]])
        b0 = get("/api/block/0")
        print("genesis msg   ", b0["transactions"][0]["inputs"][0]
              ["data_text"][:48])

        em = get("/api/emission")
        print("emission      ", em["exact_quh"], "QUH over", em["epochs"],
              "epochs")

        ct = post("/api/crypto/test", {"message": "hello"})
        print("crypto test   ", "verified", ct["verified"], "tamper caught",
              ct["tamper_detected"], f"({ct['verify_ms']}ms verify)")

        r = post("/api/miner/start", {"payout": addr, "threads": 2})
        time.sleep(2)
        post("/api/miner/stop", {})
        print("miner         ", "started" if r["ok"] else r.get("error"),
              "hashrate", r.get("miner", {}).get("hashrate"))

        r = post("/api/cli", {"args": ["chain", "info", "--json"]})
        print("cli chain info", r["ok"], r["stdout"].replace("\n", " ")[:120])

        r = post("/api/rpc", {"batch": [
            {"method": "getblockcount", "id": 1},
            {"method": "getnetworkinfo", "id": 2},
        ]})
        print("batch rpc     ", r["batch"][0]["result"],
              r["batch"][1]["result"]["network"])

        r = post("/api/rpc", {"method": "getbalance",
                              "params": {"address": "nope"}})
        print("bad address   ", r["error"]["message"][:60])

        r = post("/api/network", {"network": "testnet"})
        print("switch net    ", r["ok"], r["status"]["network"],
              "height", r["status"]["height"], "rpc", r["status"]["rpc_url"])

        print("\nALL WEB CHECKS PASSED")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        tail = proc.stdout.read()
        if tail.strip():
            print("--- server log ---")
            print(tail[-3000:])


if __name__ == "__main__":
    main()

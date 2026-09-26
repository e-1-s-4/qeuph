"""
Qeuph command line interface.

    qeuph node [--network mainnet|testnet|regtest] [--mine ADDRESS] [--connect HOST:PORT]
    qeuph wallet create  [--path FILE] [--passphrase ...]
    qeuph wallet show    [--path FILE] [--index N] [--rpc URL]
    qeuph wallet send    --to quh1... --amount QUH [--fee QUH] --from-index N --rpc URL
    qeuph wallet utxos   --index N --rpc URL
    qeuph chain info     [--network ...]
    qeuph chain block    {height|hash} [--network ...]
    qeuph chain tx       {txid} [--network ...]
    qeuph genesis        [--network ...]
    qeuph emission                          # reward schedule table
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from qeuph import constants as C
from qeuph.config import get_network
from qeuph.core import reward as reward_mod


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="qeuph",
                                description="Qeuph (QUH) quantum-resistant cryptocurrency")
    sub = p.add_subparsers(dest="cmd", required=True)

    # node --------------------------------------------------------------
    node = sub.add_parser("node", help="run the full node daemon")
    node.add_argument("--network", default="mainnet")
    node.add_argument("--mine", metavar="ADDRESS",
                      help="solo mine block rewards to ADDRESS")
    node.add_argument("--connect", action="append", metavar="HOST:PORT",
                      help="peer to connect to (repeatable)")
    node.add_argument("--rpc-host", default=C.DEFAULT_RPC_HOST)
    node.add_argument("--p2p-port", type=int, default=None,
                      help="override the P2P listen port")
    node.add_argument("--rpc-port", type=int, default=None,
                      help="override the JSON-RPC port")
    node.add_argument("--data-dir", default=None)
    node.add_argument("--seed", action="append", metavar="HOST",
                      help="DNS seed to resolve for peers (repeatable)")

    # wallet ------------------------------------------------------------
    wallet = sub.add_parser("wallet", help="wallet operations")
    wsub = wallet.add_subparsers(dest="wcmd", required=True)

    w_create = wsub.add_parser("create", help="create a new wallet")
    w_create.add_argument("--path", default=None)
    w_create.add_argument("--passphrase", default=None)
    w_create.add_argument("--network", default="mainnet")
    w_create.add_argument("--unencrypted", action="store_true",
                          help="skip encryption (testing only)")

    w_show = wsub.add_parser("show", help="show addresses and balances")
    w_show.add_argument("--path", default=None)
    w_show.add_argument("--passphrase", default=None)
    w_show.add_argument("--network", default="mainnet")
    w_show.add_argument("--count", type=int, default=1)
    w_show.add_argument("--rpc", default=None,
                        help="node RPC url, e.g. http://127.0.0.1:19091/")
    w_show.add_argument("--show-seed", action="store_true",
                        help="also print the master seed (dangerous)")

    w_send = wsub.add_parser("send", help="create, sign and broadcast a transaction")
    w_send.add_argument("--path", default=None)
    w_send.add_argument("--passphrase", default=None)
    w_send.add_argument("--network", default="mainnet")
    w_send.add_argument("--to", required=True, help="recipient quh1... address")
    w_send.add_argument("--amount", required=True, type=float, help="QUH to send")
    w_send.add_argument("--fee", type=float, default=0.01, help="fee in QUH")
    w_send.add_argument("--from-index", type=int, default=0)
    w_send.add_argument("--no-fresh-change", action="store_true",
                        help="return change to the paying address instead of a fresh one")
    w_send.add_argument("--locktime", type=int, default=0,
                        help="lock the transaction until height or unix time (0 = off)")
    w_send.add_argument("--rpc", required=True)

    w_utxos = wsub.add_parser("utxos", help="list confirmed UTXOs of an address")
    w_utxos.add_argument("--path", default=None)
    w_utxos.add_argument("--passphrase", default=None)
    w_utxos.add_argument("--network", default="mainnet")
    w_utxos.add_argument("--index", type=int, default=0)
    w_utxos.add_argument("--rpc", required=True)

    w_addr = wsub.add_parser("address", help="show the Nth address of the wallet")
    w_addr.add_argument("--path", default=None)
    w_addr.add_argument("--passphrase", default=None)
    w_addr.add_argument("--network", default="mainnet")
    w_addr.add_argument("--index", type=int, default=0)

    w_new = wsub.add_parser("newaddress", help="derive and persist the next unused address")
    w_new.add_argument("--path", default=None)
    w_new.add_argument("--passphrase", default=None)
    w_new.add_argument("--network", default="mainnet")

    w_mnem = wsub.add_parser("mnemonic", help="show 24-word backup phrase")
    w_mnem.add_argument("--path", default=None)
    w_mnem.add_argument("--passphrase", default=None)
    w_mnem.add_argument("--network", default="mainnet")

    # chain -------------------------------------------------------------
    chain = sub.add_parser("chain", help="offline chain inspection")
    csub = chain.add_subparsers(dest="ccmd", required=True)
    for name, help_ in (("info", "chain summary"), ("block", "show a block"),
                        ("tx", "show a transaction")):
        cp = csub.add_parser(name, help=help_)
        cp.add_argument("--network", default="mainnet")
        cp.add_argument("--data-dir", default=None)
        cp.add_argument("target", nargs="?", default=None,
                        help="height or hash / txid")
    cinfo = [a for a in csub.choices.values() if a.prog.endswith("info")][0]
    cinfo.add_argument("--json", action="store_true")

    # misc --------------------------------------------------------------
    gen = sub.add_parser("genesis", help="show genesis block info")
    gen.add_argument("--network", default="mainnet")
    sub.add_parser("emission", help="print the two-thirding reward schedule")
    sub.add_parser("version", help="print versions")

    # RPC client --------------------------------------------------------
    rpc_p = sub.add_parser("rpc", help="invoke JSON-RPC method")
    rpc_p.add_argument("method", help="RPC method name (e.g. getblockchaininfo)")
    rpc_p.add_argument("params", nargs="?", default="{}", help="JSON params object or string")
    rpc_p.add_argument("--url", default="http://127.0.0.1:19091/", help="RPC endpoint URL")

    # Address / Crypto tools -------------------------------------------
    addr_p = sub.add_parser("address", help="address utilities")
    addr_p.add_argument("action", choices=["validate", "info"], help="action to perform")
    addr_p.add_argument("target", help="Bech32m address to inspect")
    addr_p.add_argument("--network", default="mainnet", help="network context")

    cry_p = sub.add_parser("crypto", help="FIPS 204 crypto utilities")
    cry_p.add_argument("action", choices=["keygen", "test", "info"], help="action")
    return p


# ---------------------------------------------------------------------------
def _default_wallet_path(net) -> str:
    return net.data_dir.rstrip("/\\") + "/wallet.json"


def _open_wallet(args):
    from qeuph.wallet import Wallet
    net = get_network(args.network)
    path = args.path or _default_wallet_path(net)
    passphrase = args.passphrase
    return Wallet.open(path, passphrase, hrp=net.hrp, network=net.name)


def cmd_node(args):
    from qeuph.main import run_daemon
    net = get_network(args.network)
    if args.data_dir:
        net.data_dir = args.data_dir
    if args.p2p_port is not None:
        net.p2p_port = int(args.p2p_port)
    if args.rpc_port is not None:
        net.rpc_port = int(args.rpc_port)
    run_daemon(net, mine_to=args.mine, connect=args.connect,
               rpc_host=args.rpc_host, seed_hosts=args.seed)


def cmd_wallet(args):
    from qeuph.wallet import Wallet
    from qeuph.wallet import keystore
    net = get_network(args.network)

    if args.wcmd == "create":
        import getpass
        import os
        path = args.path or _default_wallet_path(net)
        if args.unencrypted:
            pw = None
        elif args.passphrase is not None:
            pw = args.passphrase
        else:
            while True:
                pw = getpass.getpass("passphrase: ")
                pw2 = getpass.getpass("repeat passphrase: ")
                if pw == pw2:
                    break
                print("passphrases differ, try again")
        os.makedirs(net.data_dir, exist_ok=True)
        w = Wallet.create(hrp=net.hrp, network=net.name)
        w.save(path, pw)
        print(f"wallet written to {path}")
        print(f"address 0: {w.address_at(0)}")
        print(f"cipher: {keystore.cipher_name()}")
        return

    w = _open_wallet(args)

    if args.wcmd == "address":
        print(w.address_at(args.index))
    elif args.wcmd == "newaddress":
        addr = w.new_address()
        print(addr)
    elif args.wcmd == "show":
        print(f"network: {net.name}")
        for i in range(args.count):
            addr = w.address_at(i)
            bal = ""
            if args.rpc:
                try:
                    bal = f"  balance: {w.balance(args.rpc, i) / C.QUPHI_PER_QUH} QUH"
                except Exception as e:
                    bal = f"  (rpc unavailable: {e})"
            print(f"[{i}] {addr}{bal}")
        if args.show_seed:
            print("master seed (KEEP SECRET):", w.master_seed.hex())
        else:
            print("(use --show-seed to reveal the master seed)")
    elif args.wcmd == "utxos":
        rows = w.fetch_utxos(w.address_at(args.index), args.rpc)
        total = sum(v for _, _, v in rows)
        for txid, idx, v in rows:
            print(f"{txid.hex()}:{idx}  {v / C.QUPHI_PER_QUH} QUH")
        print(f"total: {total / C.QUPHI_PER_QUH} QUH in {len(rows)} UTXOs")
    elif args.wcmd == "send":
        amount_quphi = round(args.amount * C.QUPHI_PER_QUH)
        fee_quphi = round(args.fee * C.QUPHI_PER_QUH)
        tx = w.build_transaction(args.from_index, [(args.to, amount_quphi)],
                                 fee=fee_quphi, rpc_url=args.rpc,
                                 fresh_change=not args.no_fresh_change,
                                 lock_time=args.locktime)
        txid = w.send_transaction(tx, args.rpc)
        print(f"sent {args.amount} QUH -> {args.to}")
        print(f"txid: {txid}")
        if not args.no_fresh_change:
            print("change went to a fresh wallet address "
                  "(see `qeuph wallet show --count N`)")
    elif args.wcmd == "mnemonic":
        phrase = w.to_mnemonic()
        print("24-word recovery phrase (KEEP SECRET):")
        print(phrase)


def cmd_chain(args):
    from qeuph.core.chain import ChainManager
    net = get_network(args.network)
    if args.data_dir:
        net.data_dir = args.data_dir
    cm = ChainManager(net)
    try:
        if args.ccmd == "info":
            from qeuph.core import pow as pow_mod
            info = {
                "network": net.name,
                "height": cm.height(),
                "tip": cm.tip_hash().hex(),
                "difficulty": pow_mod.difficulty_from_bits(cm.tip.header.bits),
                "next_bits": hex(cm.next_bits()),
                "next_reward": cm.block_reward(),
                "genesis": cm.genesis.hash.hex(),
            }
            print(json.dumps(info, indent=2) if args.json else
                  "\n".join(f"{k}: {v}" for k, v in info.items()))
        elif args.ccmd == "block":
            from qeuph.core.block import Block
            target = args.target
            b = None
            if target is None or str(target).isdigit() and len(str(target)) < 12:
                b = cm.get_block_by_height(int(target or 0))
            else:
                b = cm.get_block(bytes.fromhex(target))
            if b is None:
                print("block not found")
                sys.exit(1)
            d = b.to_dict(net.hrp)
            d.pop("transactions", None)     # keep output readable
            print(json.dumps(d, indent=2))
        elif args.ccmd == "tx":
            if cm.store is None:
                print("tx lookup requires persistence")
                sys.exit(1)
            loc = cm.store.get_tx_block(bytes.fromhex(args.target))
            if loc is None:
                print("transaction not found")
                sys.exit(1)
            height, bh = loc
            blk = cm.get_block(bh)
            for tx in (blk.transactions if blk else []):
                if tx.txid().hex() == args.target:
                    print(json.dumps(tx.to_dict(net.hrp), indent=2))
                    return
    finally:
        if cm.store:
            cm.store.close()


def cmd_genesis(args):
    from qeuph.core import genesis as genesis_mod
    net = get_network(args.network)
    g = genesis_mod.build_genesis(net)
    print(json.dumps(g.header.to_dict(), indent=2))
    print("coinbase message:", net.genesis_message)


def cmd_emission(_args):
    rows = reward_mod.emission_table()
    print(f"{'epoch':>5} {'start height':>12} {'reward (QUH)':>18} "
          f"{'cumulative (QUH)':>22}")
    for e, h, r, rq, cum in rows:
        print(f"{e:>5} {h:>12} {rq:>18,.8f} {cum / C.QUPHI_PER_QUH:>22,.3f}")
    print(f"\ncap: {C.MAX_SUPPLY_QUH:,} QUH")
    exact = reward_mod.exact_total_emission()
    print(f"exact floored emission: {exact:,} quphi "
          f"({exact / C.QUPHI_PER_QUH:.8f} QUH)")


def cmd_rpc(args):
    import urllib.request
    import urllib.error
    url = args.url
    params = {}
    if args.params:
        try:
            params = json.loads(args.params)
        except Exception:
            params = args.params
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": args.method, "params": params}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            doc = json.loads(resp.read().decode())
            if "result" in doc:
                print(json.dumps(doc["result"], indent=2))
            else:
                print(json.dumps(doc, indent=2))
    except urllib.error.HTTPError as err:
        try:
            print(json.dumps(json.loads(err.read().decode()), indent=2))
        except Exception:
            print(f"HTTP {err.code}: {err.reason}")
    except Exception as e:
        print(f"RPC connection failed ({url}): {e}")


def cmd_address(args):
    from qeuph.crypto import address as addr_mod
    net = get_network(args.network)
    addr = args.target.strip()
    ahash = addr_mod.address_to_hash(addr, net.hrp)
    is_valid = ahash is not None and len(ahash) == 64
    if args.action == "validate":
        print(json.dumps({
            "address": addr,
            "network": net.name,
            "hrp": net.hrp,
            "valid": is_valid,
            "addr_hash": ahash.hex() if is_valid else None
        }, indent=2))
    elif args.action == "info":
        if not is_valid:
            print(f"Invalid {net.hrp} address")
            sys.exit(1)
        print(f"Address:   {addr}")
        print(f"HRP:       {net.hrp}")
        print(f"Hash (64B):{ahash.hex()}")
        print(f"Encoding:  Bech32m (BIP-350)")


def cmd_crypto(args):
    from qeuph.crypto import ml_dsa
    if args.action == "keygen":
        seed, pk, sk = ml_dsa.generate_keypair()
        from qeuph.crypto import address as addr_mod
        from qeuph import constants as C
        addr = addr_mod.pk_to_address(pk, C.ADDRESS_HRP_MAINNET)
        print("ML-DSA-87 (FIPS 204) Keypair:")
        print(f"Master Seed: {seed.hex()}")
        print(f"Public Key:  {pk.hex()[:64]}... ({len(pk)} bytes)")
        print(f"Secret Key:  {sk.hex()[:64]}... ({len(sk)} bytes)")
        print(f"Mainnet Addr:{addr}")
    elif args.action == "test":
        print("Running FIPS 204 ML-DSA-87 Roundtrip...")
        msg = b"Qeuph Post-Quantum Cryptographic Verification"
        seed, pk, sk = ml_dsa.generate_keypair()
        sig = ml_dsa.sign(sk, msg)
        valid = ml_dsa.verify(pk, msg, sig)
        tamper = ml_dsa.verify(pk, msg + b"X", sig)
        print(f"Backend:  {ml_dsa.backend_name()}")
        print(f"Verified: {valid}")
        print(f"Tamper detected: {not tamper}")
    elif args.action == "info":
        print("FIPS 204 ML-DSA-87 Parameters (NIST Category 5):")
        print(f"Backend:     {ml_dsa.backend_name()}")
        print(f"PK Size:     {ml_dsa.PK_SIZE} bytes")
        print(f"SK Size:     {ml_dsa.SK_SIZE} bytes")
        print(f"Sig Size:    {ml_dsa.SIG_SIZE} bytes")
        print("Security:    256-bit Post-Quantum Lattice (Module-LWE/SIS)")


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "node":
        cmd_node(args)
    elif args.cmd == "wallet":
        cmd_wallet(args)
    elif args.cmd == "chain":
        cmd_chain(args)
    elif args.cmd == "genesis":
        cmd_genesis(args)
    elif args.cmd == "emission":
        cmd_emission(args)
    elif args.cmd == "rpc":
        cmd_rpc(args)
    elif args.cmd == "address":
        cmd_address(args)
    elif args.cmd == "crypto":
        cmd_crypto(args)
    elif args.cmd == "version":
        from qeuph import __version__
        print(f"qeuph {__version__} protocol {C.PROTOCOL_VERSION}")


if __name__ == "__main__":
    main()


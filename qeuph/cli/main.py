"""
Qeuph command line interface.

This module is the canonical description of what a Qeuph node can do; the
web UI in `qeuph.web.server` mirrors these same subcommands and RPC methods
over HTTP so the two surfaces can never drift apart.

    qeuph [global flags] <command> ...

node
    qeuph node       --network N [--mine ADDR] [--threads N] [--connect H:P]
                      [--seed HOST] [--rpc-host H] [--rpc-port P]
                      [--p2p-port P] [--rpc-user U --rpc-password P]
                      [--data-dir D] [--log-file F] [--verbose]
    qeuph mine       --address ADDR [--threads N] [--network N]   (offline
                      PoW search against the current tip; used to benchmark)

wallet
    qeuph wallet create   [--path F] [--passphrase P] [--network N]
    qeuph wallet show     [--path F] [--count N] [--rpc URL]
    qeuph wallet balance  [--path F] [--index N] [--rpc URL]
    qeuph wallet send     --to ADDR --amount QUH [--fee QUH] [--index N]
                          [--locktime N] [--rpc URL]
    qeuph wallet utxos    [--index N] [--rpc URL]
    qeuph wallet address  [--index N]
    qeuph wallet newaddress
    qeuph wallet mnemonic
    qeuph wallet backup   --out F | --out-mnemonic
    qeuph wallet restore  --from-mnemonic "..." | --in F
    qeuph wallet sweep    --to ADDR [--index N] [--rpc URL] [--broadcast]
    qeuph wallet sign     --file F [--index N] [--out F]
    qeuph wallet verify   --file F
    qeuph wallet passwd

chain
    qeuph chain info      [--network N] [--json]
    qeuph chain blocks    [--network N] [--limit N]
    qeuph chain block     {height|hash} [--network N]
    qeuph chain tx        {txid} [--network N]
    qeuph chain verify    [--network N] [--limit N]
    qeuph chain reindex   [--network N] [--keep-side-chains]
    qeuph chain truncate  --height H [--network N]

rpc
    qeuph rpc METHOD ['{"json": "params"}'] [--url URL] [--user U --password P]

tools
    qeuph preflight   [--network N] [--connect H:P] [--seed HOST] [--json]
    qeuph genesis     [--network N]
    qeuph emission    [--json]
    qeuph address     {validate|info} ADDR [--network N]
    qeuph crypto      {keygen|test|info|bench} [--network N]
    qeuph web         [--host H] [--port P] [--network N]   (node explorer UI)
    qeuph version
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Optional

from qeuph import constants as C
from qeuph.config import get_network
from qeuph.core import reward as reward_mod
from qeuph.wallet.keystore import WalletError


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------
def default_rpc_url(net) -> str:
    return f"http://{C.DEFAULT_RPC_HOST}:{net.default_rpc_port}/"


def build_parser() -> argparse.ArgumentParser:
    # allow_abbrev=False everywhere: the web route's "never return key
    # material" refusal inspects option names, and argparse's unambiguous
    # prefix matching let `wallet backup --out-mnem` and
    # `wallet show --show-s` run the blocked commands anyway.  Exact names
    # also keep the browser's option list, which is generated from this same
    # parser, honest.
    p = argparse.ArgumentParser(
        prog="qeuph",
        description="Qeuph (QUH) quantum-resistant cryptocurrency",
        epilog="See `qeuph <command> --help` for details, or the README.",
        allow_abbrev=False)
    p.add_argument("--version", action="store_true",
                   help="print the version and exit")
    sub = p.add_subparsers(dest="cmd")

    # ---------------------------------------------------------------- node
    node = sub.add_parser("node", help="run the full node daemon")
    node.add_argument("--network", default=None,
                      choices=["mainnet", "testnet", "regtest"])
    node.add_argument("--mine", metavar="ADDRESS",
                      help="solo mine block rewards to ADDRESS")
    node.add_argument("--threads", type=int, default=1,
                      help="solo miner worker threads (default 1, max 16)")
    node.add_argument("--connect", action="append", metavar="HOST:PORT",
                      help="peer to connect to (repeatable)")
    node.add_argument("--seed", action="append", metavar="HOST",
                      help="DNS seed to resolve for peers (repeatable)")
    node.add_argument("--rpc-host", default=C.DEFAULT_RPC_HOST)
    node.add_argument("--p2p-host", default="0.0.0.0",
                      help="interface the P2P listener binds (default: all)")
    node.add_argument("--p2p-port", type=int, default=None)
    node.add_argument("--rpc-port", type=int, default=None)
    node.add_argument("--rpc-user", default=None, help="RPC basic-auth user")
    node.add_argument("--rpc-password", default=None, help="RPC basic-auth password")
    node.add_argument("--max-peers", type=int, default=C.MAX_PEERS)
    node.add_argument("--data-dir", default=None)
    node.add_argument("--log-file", default=None)
    node.add_argument("--verbose", action="store_true")

    mine = sub.add_parser("mine", help="offline PoW benchmark against the tip")
    mine.add_argument("--address", required=True, metavar="ADDRESS")
    mine.add_argument("--network", default=None)
    mine.add_argument("--data-dir", default=None)
    mine.add_argument("--seconds", type=float, default=10.0)
    mine.add_argument("--threads", type=int, default=1)

    pre = sub.add_parser(
        "preflight",
        help="check this build, a network and the local ports for launch "
             "readiness (starts nothing, mines nothing)")
    pre.add_argument("--network", default=None,
                     choices=["mainnet", "testnet", "regtest"])
    pre.add_argument("--connect", action="append", metavar="HOST:PORT",
                     help="peer that would be passed to `node --connect`")
    pre.add_argument("--seed", action="append", metavar="HOST",
                     help="DNS seed that would be passed to `node --seed`")
    pre.add_argument("--rpc-host", default=C.DEFAULT_RPC_HOST)
    pre.add_argument("--rpc-port", type=int, default=None)
    pre.add_argument("--p2p-port", type=int, default=None)
    pre.add_argument("--rpc-user", default=None)
    pre.add_argument("--rpc-password", default=None)
    pre.add_argument("--data-dir", default=None)
    pre.add_argument("--json", action="store_true")

    # -------------------------------------------------------------- wallet
    wallet = sub.add_parser("wallet", help="wallet operations")
    wsub = wallet.add_subparsers(dest="wcmd", required=True)

    def wcommon(sp, need_rpc=False):
        sp.add_argument("--path", default=None, help="wallet file")
        sp.add_argument("--passphrase", default=None,
                        help="wallet passphrase (prompted if omitted)")
        sp.add_argument("--network", default=None)
        if need_rpc:
            sp.add_argument("--rpc", default=None, help="node RPC url")
        return sp

    wcommon(wsub.add_parser("create", help="create a new wallet"))
    wsub.choices["create"].add_argument("--unencrypted", action="store_true",
                                       help="no passphrase (testing only)")
    wcommon(wsub.add_parser("show", help="show addresses and balances"),
            need_rpc=True).add_argument("--count", type=int, default=1)
    wcommon(wsub.add_parser("balance", help="show the confirmed balance"),
            need_rpc=True).add_argument("--index", type=int, default=0)
    w_show = wsub.choices["show"]
    w_show.add_argument("--index", type=int, default=0)
    w_show.add_argument("--show-seed", action="store_true",
                        help="also print the master seed (dangerous)")

    w_send = wcommon(wsub.add_parser("send", help="sign and broadcast a payment"),
                     need_rpc=True)
    w_send.add_argument("--to", required=True, help="recipient address")
    w_send.add_argument("--amount", required=True, type=float, help="amount in QUH")
    w_send.add_argument("--fee", type=float, default=0.01, help="fee in QUH")
    w_send.add_argument("--index", type=int, default=0)
    w_send.add_argument("--no-fresh-change", action="store_true")
    w_send.add_argument("--locktime", type=int, default=0,
                        help="lock until this height (or unix time if >= 5e8)")
    w_send.add_argument("--dry-run", action="store_true",
                        help="build and print the transaction, do not relay")

    wcommon(wsub.add_parser("utxos", help="list confirmed UTXOs"),
            need_rpc=True).add_argument("--index", type=int, default=0)
    wcommon(wsub.add_parser("address", help="print the Nth address")
            ).add_argument("--index", type=int, default=0)
    wcommon(wsub.add_parser("newaddress", help="derive the next fresh address"))
    wcommon(wsub.add_parser("mnemonic", help="print the 24-word recovery phrase"))
    wcommon(wsub.add_parser("passwd", help="change the wallet passphrase"))

    w_backup = wcommon(wsub.add_parser("backup", help="export seed / phrase"))
    w_backup.add_argument("--out", default=None, metavar="FILE",
                          help="write an encrypted wallet copy here")
    w_backup.add_argument("--out-mnemonic", action="store_true",
                          help="print the recovery phrase instead")
    w_backup.add_argument("--new-passphrase", default=None,
                          help="passphrase for the copy written by --out")

    w_restore = wcommon(wsub.add_parser("restore", help="rebuild from a backup"))
    w_restore.add_argument("--from-mnemonic", default=None, metavar="PHRASE")
    w_restore.add_argument("--in", dest="infile", default=None, metavar="FILE")
    w_restore.add_argument("--unencrypted", action="store_true",
                           help="write the restored wallet without a passphrase")

    w_sweep = wcommon(wsub.add_parser("sweep", help="send every output to one address"),
                      need_rpc=True)
    w_sweep.add_argument("--to", required=True)
    w_sweep.add_argument("--index", type=int, default=0)
    w_sweep.add_argument("--broadcast", action="store_true",
                         help="actually relay (default: dry run)")

    w_sign = wcommon(wsub.add_parser("sign", help="sign a raw transaction"))
    w_sign.add_argument("--file", required=True, help="hex or file with the raw tx")
    w_sign.add_argument("--index", type=int, default=0)
    w_sign.add_argument("--out", default=None, help="write the signed hex here")

    wcommon(wsub.add_parser("verify", help="verify a signed transaction")
            ).add_argument("--file", required=True)

    # --------------------------------------------------------------- chain
    chain = sub.add_parser("chain", help="offline chain inspection")
    csub = chain.add_subparsers(dest="ccmd", required=True)
    for name, help_ in (("info", "chain summary"),
                        ("blocks", "recent blocks"),
                        ("block", "show a block"),
                        ("tx", "show a transaction"),
                        ("verify", "re-validate the canonical chain"),
                        ("reindex", "rebuild the index and UTXO tables"),
                        ("truncate", "delete blocks above a height")):
        cp = csub.add_parser(name, help=help_)
        cp.add_argument("--network", default=None)
        cp.add_argument("--data-dir", default=None)
        cp.add_argument("--json", action="store_true")
        if name in ("block", "tx"):
            cp.add_argument("target", nargs="?", default=None)
        if name == "blocks":
            cp.add_argument("--limit", type=int, default=15)
        if name == "verify":
            cp.add_argument("--limit", type=int, default=None)
        if name == "reindex":
            cp.add_argument("--keep-side-chains", action="store_true")
        if name == "truncate":
            cp.add_argument("--height", type=int, required=True)

    # ----------------------------------------------------------------- rpc
    rpc_p = sub.add_parser("rpc", help="invoke a JSON-RPC method")
    rpc_p.add_argument("method")
    rpc_p.add_argument("params", nargs="?", default="{}")
    rpc_p.add_argument("--url", default=None)
    rpc_p.add_argument("--user", default=None)
    rpc_p.add_argument("--password", default=None)

    # --------------------------------------------------------------- tools
    sub.add_parser("genesis", help="show the genesis block").add_argument(
        "--network", default=None)
    sub.add_parser("emission", help="print the two-thirding schedule").add_argument(
        "--json", action="store_true")
    sub.add_parser("version", help="print version information")

    addr_p = sub.add_parser("address", help="address utilities")
    addr_p.add_argument("action", choices=["validate", "info"])
    addr_p.add_argument("target")
    addr_p.add_argument("--network", default=None)

    cry_p = sub.add_parser("crypto", help="FIPS 204 utilities")
    cry_p.add_argument("action", choices=["keygen", "test", "info", "bench"])
    cry_p.add_argument("--network", default=None)

    web = sub.add_parser("web", help="serve the node explorer / wallet UI")
    web.add_argument("--host", default=C.DEFAULT_WEB_HOST)
    web.add_argument("--port", type=int, default=C.DEFAULT_WEB_PORT)
    web.add_argument("--network", default="regtest",
                     help="network for the embedded node (default: regtest, "
                          "NOT mainnet)")
    web.add_argument("--data-dir", default=None)
    web.add_argument("--embedded-node", default=None,
                     choices=["regtest", "testnet", "mainnet", "off"],
                     help="run a node in-process (default: regtest); 'off' "
                          "attaches the UI to --remote-rpc instead")
    web.add_argument("--remote-rpc", default=None, metavar="URL",
                     help="with --embedded-node off: JSON-RPC URL of the "
                          "external node this UI attaches to (e.g. "
                          "http://127.0.0.1:19091/)")
    web.add_argument("--connect", action="append", metavar="HOST:PORT",
                     help="P2P peer the embedded node dials (repeatable); "
                          "joins the mesh formed by `qeuph node` daemons")
    web.add_argument("--p2p-host", default="127.0.0.1",
                     help="interface the embedded node's P2P listener binds "
                          "(default: loopback)")
    web.add_argument("--allow-remote", action="store_true",
                     help="permit a non-loopback bind (you own the firewall)")

    # allow_abbrev is a per-parser setting, so the flag on the root parser
    # does not reach the subcommands - apply it across the whole tree.
    def _no_abbrev(parser, seen=None):
        seen = seen if seen is not None else set()
        if id(parser) in seen:
            return
        seen.add(id(parser))
        parser.allow_abbrev = False
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                for sub_p in action.choices.values():
                    _no_abbrev(sub_p, seen)

    _no_abbrev(p)
    return p


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _net(args):
    return get_network(getattr(args, "network", None))


def _with_data_dir(net, data_dir):
    return net.with_(data_dir=data_dir) if data_dir else net


def _to_quphi(value, label: str) -> int:
    """Convert a decimal QUH amount to quphi, exactly.

    `round(x * 10**8)` on a binary float is lossy and applies banker's
    rounding, so `--amount 0.000000005` silently became 0 and other values
    landed a quphi or two away from what was typed.  Decimal parses the
    literal the user actually wrote.
    """
    from decimal import Decimal, InvalidOperation
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        raise SystemExit(f"{label} {value!r} is not a number")
    scaled = d.scaleb(C.DECIMALS)
    if scaled != scaled.to_integral_value():
        # more precision than a quphi: refuse rather than round silently
        raise SystemExit(
            f"{label} {value!r} has more than {C.DECIMALS} decimal places")
    q = int(scaled)
    if q < 0:
        raise SystemExit(f"{label} must not be negative")
    if q > (1 << 64) - 1:
        raise SystemExit(f"{label} exceeds the 64-bit quphi range")
    return q


def _default_wallet_path(net) -> str:
    return os.path.join(net.data_dir, "wallet.json")


def _read_passphrase(args, prompt="passphrase") -> Optional[str]:
    """Resolve a wallet passphrase without hanging in a non-interactive run.

    Order: --passphrase, then $QEUPH_WALLET_PASSPHRASE, then an interactive
    prompt when stdin is a terminal.  A pipe with no passphrase given is an
    error, not a hang.
    """
    explicit = getattr(args, "passphrase", None)
    if explicit is not None:
        return explicit
    if getattr(args, "unencrypted", False):
        return None
    env = os.environ.get("QEUPH_WALLET_PASSPHRASE")
    if env is not None:
        return env
    if not (sys.stdin is not None and sys.stdin.isatty()):
        raise SystemExit(
            "no wallet passphrase available: pass --passphrase, set "
            "$QEUPH_WALLET_PASSPHRASE, or run on a terminal to be prompted")
    import getpass
    return getpass.getpass(f"{prompt}: ")


def _open_wallet(args, net):
    from qeuph.wallet import Wallet
    path = args.path or _default_wallet_path(net)
    passphrase = _read_passphrase(args)
    return Wallet.open(path, passphrase, hrp=net.hrp, network=net.name)


def _rpc_url(args, net) -> str:
    return getattr(args, "rpc", None) or default_rpc_url(net)


def _open_chain(net):
    from qeuph.core.chain import ChainManager
    return ChainManager(net)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_node(args):
    from qeuph.main import run_daemon
    net = _net(args)
    net = _with_data_dir(net, args.data_dir)
    if args.p2p_port is not None:
        net = net.with_(p2p_port=int(args.p2p_port))
    if args.rpc_port is not None:
        net = net.with_(rpc_port=int(args.rpc_port))
    run_daemon(net, mine_to=args.mine, connect=args.connect,
               rpc_host=args.rpc_host, seed_hosts=args.seed,
               rpc_user=args.rpc_user, rpc_password=args.rpc_password,
               miner_threads=args.threads, verbose=args.verbose,
               logfile=args.log_file)


def cmd_mine(args):
    from qeuph.core import pow as pow_mod
    from qeuph.crypto import address as addr_mod
    net = _with_data_dir(_net(args), args.data_dir)
    ahash = addr_mod.address_to_hash(args.address, net.hrp)
    if ahash is None:
        sys.exit(f"invalid {net.hrp} address: {args.address}")
    cm = _open_chain(net)
    try:
        bits = cm.tip.header.bits
        target = pow_mod.bits_to_target(bits)
        diff = pow_mod.difficulty_from_bits(bits)
        print(f"network   {net.name}")
        print(f"height    {cm.height()}")
        print(f"bits      {hex(bits)}   difficulty {diff:,.4f}")
        print(f"expected  {target:,.0f} hashes per block")
        print(f"benchmark {args.seconds:.0f}s x {args.threads} thread(s)")
        total, best = _bench(args, net, ahash, cm, target)
    finally:
        cm.close()
    if total <= 0:
        sys.exit("benchmark produced no hashes")
    print(f"\ntotal hashrate     {total:,.1f} H/s")
    print(f"best thread        {best:,.1f} H/s")
    print(f"expected block     {target / total:,.1f} s "
          f"({target / total / 60:.1f} min) at difficulty {diff:,.2f}")
    share = 100.0 / diff if diff else 0.0
    print(f"network share      ~{share:.6f}% (at this hashrate)")


def _bench(args, net, ahash, cm, target):
    """Hash N seconds on the current template; returns (H/s, best thread H/s)."""
    import threading
    from qeuph.core import pow as pow_mod
    results = []

    def run(idx):
        block, _ = cm.create_block_template(ahash, [], extra_nonce=b"bench")
        header = block.header.serialize()
        bits = block.header.bits
        n = 0
        end = time.time() + args.seconds
        while time.time() < end:
            for _nonce in pow_mod.mine_range(header, bits, n, 1 << 14):
                pass
            n += 1 << 14
        results.append(n / args.seconds)

    workers = [threading.Thread(target=run, args=(i,), daemon=True)
               for i in range(args.threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(args.seconds + 10)
    if not results:
        return 0.0, 0.0
    return sum(results), (max(results) if len(results) > 1 else results[0])


def cmd_wallet(args):
    from qeuph.wallet import Wallet
    from qeuph.wallet import keystore
    net = _net(args)
    path = args.path or _default_wallet_path(net)

    if args.wcmd == "create":
        if os.path.exists(path) and not args.unencrypted:
            if not sys.stdin.isatty():
                sys.exit(f"wallet file {path} already exists; "
                         f"pass --path to write elsewhere or remove it first")
            if input(f"wallet file {path} exists; overwrite? [y/N] ").lower() != "y":
                print("aborted")
                return
        pw = _read_passphrase(args) if not args.unencrypted else None
        if pw is not None and not args.passphrase and \
                os.environ.get("QEUPH_WALLET_PASSPHRASE") is None:
            import getpass
            if sys.stdin.isatty():
                if pw != getpass.getpass("repeat passphrase: "):
                    sys.exit("passphrases differ")
        w = Wallet.create(hrp=net.hrp, network=net.name)
        w.save(path, pw)
        print(f"wallet written to {path}")
        print(f"network      {net.name} (hrp {net.hrp})")
        print(f"cipher       {keystore.cipher_name()}")
        print("kdf          pbkdf2-hmac-sha3-512, "
              f"{keystore.kdf_iterations()} iterations")
        print(f"address 0    {w.address_at(0)}")
        print()
        print("*** BACK UP THE RECOVERY PHRASE NOW ***")
        print(w.to_mnemonic())
        print("*** anyone with this phrase controls every derived address ***")
        return

    if args.wcmd == "backup":
        if args.out_mnemonic:
            w = _open_wallet(args, net)
            print(w.to_mnemonic())
            return
        if not args.out:
            sys.exit("backup needs --out FILE or --out-mnemonic")
        w = _open_wallet(args, net)
        # the copy gets its own passphrase: the current one only opened the
        # source wallet
        new_pw = args.new_passphrase
        if new_pw is None:
            if not sys.stdin.isatty():
                sys.exit("give the copy a passphrase with --new-passphrase "
                         "(or --out-mnemonic to print the phrase instead)")
            import getpass
            new_pw = getpass.getpass("passphrase for the copy: ")
            if new_pw != getpass.getpass("repeat passphrase: "):
                sys.exit("passphrases differ")
        w.save(args.out, new_pw)
        print(f"wallet copy written to {args.out}")
        return

    if args.wcmd == "restore":
        phrase = args.from_mnemonic
        if not phrase and args.infile:
            with open(args.infile) as f:
                doc = json.load(f)
            if "aes" in doc or "fallback" in doc:
                src = _open_wallet(args, net)
                phrase = src.to_mnemonic()
            else:
                phrase = doc.get("mnemonic", "").strip()
        if not phrase:
            sys.exit("restore needs --from-mnemonic PHRASE or --in FILE")
        pw = (_read_passphrase(args, "passphrase for the restored wallet")
              if not getattr(args, "unencrypted", False) else None)
        w = Wallet.from_mnemonic(phrase, hrp=net.hrp, network=net.name)
        w.save(path, pw)
        print(f"wallet restored to {path}")
        print(f"address 0    {w.address_at(0)}")
        return

    if args.wcmd == "passwd":
        from qeuph.wallet import keystore as ks
        if not os.path.exists(path):
            sys.exit(f"no wallet at {path}")
        import getpass
        if not sys.stdin.isatty():
            sys.exit("`wallet passwd` needs a terminal")
        old = getpass.getpass("current passphrase: ")
        new = getpass.getpass("new passphrase: ")
        if new != getpass.getpass("repeat new passphrase: "):
            sys.exit("passphrases differ")
        ks.reencrypt(path, old, new)
        print("passphrase changed")
        return

    if args.wcmd == "verify":
        raw = _read_raw(args.file)
        from qeuph.core.tx import Transaction
        from qeuph.crypto import ml_dsa
        try:
            # lenient parse: `wallet verify` must be able to report on an
            # unsigned transaction, which is the case it is most used for
            tx = Transaction.deserialize(bytes.fromhex(raw),
                                         allow_unsigned=True)
        except Exception as e:
            sys.exit(f"cannot decode transaction: {e}")
        bad = 0
        for i, inp in enumerate(tx.inputs):
            ok = ml_dsa.verify(inp.pubkey, tx.signing_message(i), inp.signature)
            if not ok:
                bad += 1
        print(f"txid          {tx.txid().hex()}")
        print(f"inputs        {len(tx.inputs)} ({len(tx.inputs) - bad} valid "
              f"signatures, {bad} invalid)")
        print(f"outputs       {len(tx.outputs)} totalling "
              f"{tx.total_out / C.QUPHI_PER_QUH:.8f} QUH")
        print(f"size          {tx.size()} bytes")
        print(f"lock_time     {tx.lock_time}")
        sys.exit(1 if bad else 0)

    if args.wcmd == "sign":
        raw = _read_raw(args.file)
        from qeuph.core.tx import Transaction
        w = _open_wallet(args, net)
        try:
            # lenient parse: signing is what turns an unsigned transaction
            # into a valid one, so that is the normal input
            tx = Transaction.deserialize(bytes.fromhex(raw),
                                         allow_unsigned=True)
        except Exception as e:
            sys.exit(f"cannot decode transaction: {e}")
        w.sign_transaction(tx, args.index)
        signed = tx.serialize().hex()
        if args.out:
            with open(args.out, "w") as f:
                f.write(signed)
            print(f"signed transaction written to {args.out}")
        else:
            print(signed)
        print(f"txid {tx.txid().hex()}")
        return

    w = _open_wallet(args, net)

    if args.wcmd == "address":
        print(w.address_at(args.index))
    elif args.wcmd == "newaddress":
        print(w.new_address())
    elif args.wcmd == "mnemonic":
        print("24-word recovery phrase (KEEP SECRET, NEVER SHARE):")
        print(w.to_mnemonic())
    elif args.wcmd == "show":
        rpc = _rpc_url(args, net)
        print(f"network {net.name}  hrp {net.hrp}  file {w.path or path}")
        for i in range(args.count):
            addr = w.address_at(i)
            line = f"[{i}] {addr}"
            if args.rpc or net.is_regtest:
                try:
                    bal = w.balance(rpc, i)
                    line += f"  {bal / C.QUPHI_PER_QUH:.8f} QUH"
                except Exception as e:
                    line += f"  (rpc: {e})"
            print(line)
        if args.show_seed:
            print("master seed (KEEP SECRET):", w.master_seed.hex())
    elif args.wcmd == "balance":
        rpc = _rpc_url(args, net)
        bal = w.balance(rpc, args.index)
        mat = w.matured_balance(rpc, args.index)
        addr = w.address_at(args.index)
        print(f"address        {addr}")
        print(f"balance        {bal} quphi ({bal / C.QUPHI_PER_QUH:.8f} QUH)")
        print(f"spendable      {mat} quphi ({mat / C.QUPHI_PER_QUH:.8f} QUH)")
        print(f"txnonce        {w.fetch_nonce(addr, rpc)}")
    elif args.wcmd == "utxos":
        rpc = _rpc_url(args, net)
        rows = w.fetch_utxos(w.address_at(args.index), rpc)
        total = sum(v for _, _, v in rows)
        for txid, idx, v in rows:
            print(f"{txid.hex()}:{idx}  {v / C.QUPHI_PER_QUH:.8f} QUH")
        print(f"total: {total / C.QUPHI_PER_QUH:.8f} QUH in {len(rows)} UTXOs")
    elif args.wcmd == "send":
        rpc = _rpc_url(args, net)
        amount_quphi = _to_quphi(args.amount, "amount")
        fee_quphi = _to_quphi(args.fee, "fee")
        tx = w.build_transaction(args.index, [(args.to, amount_quphi)],
                                 fee=fee_quphi, rpc_url=rpc,
                                 fresh_change=not args.no_fresh_change,
                                 lock_time=args.locktime)
        if args.dry_run:
            print(json.dumps(tx.to_dict(net.hrp), indent=2))
            print("\n(dry run: nothing was relayed)")
            return
        txid = w.send_transaction(tx, rpc)
        print(f"sent {args.amount} QUH -> {args.to}")
        print(f"fee     {args.fee} QUH")
        print(f"txid    {txid}")
        print(f"size    {tx.size()} bytes")
        for i, o in enumerate(tx.outputs):
            from qeuph.crypto import address as addr_mod
            print(f"  out[{i}] {o.value / C.QUPHI_PER_QUH:.8f} QUH -> "
                  f"{addr_mod.hash_to_address(o.addr_hash, net.hrp)}")
    elif args.wcmd == "sweep":
        rpc = _rpc_url(args, net)
        txs = w.sweep(args.index, args.to, rpc)
        print(f"{len(txs)} transaction(s) prepared for {args.to}")
        for tx in txs:
            if args.broadcast:
                txid = w.send_transaction(tx, rpc)
                print(f"  relayed {txid}")
            else:
                print(f"  {tx.txid().hex()}  (dry run, "
                      f"{tx.size()} bytes, use --broadcast)")
        if not args.broadcast:
            print("\n(dry run: nothing was relayed)")


def _read_raw(spec: str) -> str:
    if os.path.exists(spec):
        with open(spec) as f:
            return f.read().strip()
    return spec.strip()


def cmd_chain(args):
    net = _with_data_dir(_net(args), args.data_dir)
    cm = _open_chain(net)
    try:
        if args.ccmd == "info":
            from qeuph.core import pow as pow_mod
            info = {
                "network": net.name,
                "height": cm.height(),
                "tip": cm.tip_hash().hex(),
                "difficulty": pow_mod.difficulty_from_bits(cm.tip.header.bits),
                "bits": hex(cm.tip.header.bits),
                "next_bits": hex(cm.next_bits()),
                "next_reward": cm.block_reward(),
                "next_reward_quh": cm.block_reward() / C.QUPHI_PER_QUH,
                "mediantime": cm.median_time_past(),
                "genesis": cm.genesis.hash.hex(),
                "utxos": len(cm.state.utxos),
                "stored_blocks": cm.store.count_blocks() if cm.store else 0,
                "reorgs": cm.reorg_count,
                "orphans": cm.orphan_count(),
            }
            _emit(args, info)
        elif args.ccmd == "blocks":
            out = []
            for h in range(cm.height(), max(-1, cm.height() - args.limit), -1):
                b = cm.get_block_by_height(h)
                if b is None:
                    continue
                out.append(b.summary(net.hrp, cm.height() - h + 1))
            _emit(args, out)
        elif args.ccmd == "block":
            target = args.target
            b = None
            if target is None or (str(target).isdigit() and len(str(target)) < 12):
                b = cm.get_block_by_height(int(target or 0))
            else:
                try:
                    b = cm.get_block(bytes.fromhex(target))
                except ValueError:
                    sys.exit("bad block hash")
            if b is None:
                sys.exit("block not found")
            d = b.to_dict(net.hrp)
            d["confirmations"] = cm.height() - b.height + 1
            _emit(args, d)
        elif args.ccmd == "tx":
            if cm.store is None:
                sys.exit("tx lookup requires persistence")
            loc = cm.store.get_tx_block(bytes.fromhex(args.target))
            if loc is None:
                sys.exit("transaction not found")
            height, bh = loc
            blk = cm.get_block(bh)
            for tx in (blk.transactions if blk else []):
                if tx.txid().hex() == args.target:
                    d = tx.to_dict(net.hrp)
                    d.update({"height": height, "block_hash": bh.hex(),
                              "confirmations": cm.height() - height + 1})
                    _emit(args, d)
                    return
            sys.exit("transaction not found")
        elif args.ccmd == "verify":
            _emit(args, cm.verify_chain(args.limit))
        elif args.ccmd == "reindex":
            report = cm.reindex(prune=True,
                                drop_side=not args.keep_side_chains)
            _emit(args, report)
        elif args.ccmd == "truncate":
            n = cm.store.truncate_to_height(args.height)
            _emit(args, {"removed_blocks": n,
                         "note": "restart the node to rebuild state from the "
                                 "truncated index, or run `qeuph chain reindex`"})
    finally:
        cm.close()


def _emit(args, value):
    if getattr(args, "json", False):
        print(json.dumps(value, indent=2))
    elif isinstance(value, list):
        for row in value:
            print(json.dumps(row))
    elif isinstance(value, dict):
        width = max((len(k) for k in value), default=0)
        for k, v in value.items():
            print(f"{k.ljust(width)} : {v}")
    else:
        print(value)


def cmd_genesis(args):
    from qeuph.core import genesis as genesis_mod
    net = _net(args)
    g = genesis_mod.build_genesis(net)
    info = g.header.to_dict()
    info["meets_target"] = g.header.meets_target()
    info["message"] = net.genesis_message
    info["valid"] = genesis_mod.validate_genesis(g, net)
    pinned = C.CHECKPOINTS.get(0) if net.is_mainnet else None
    if pinned is not None:
        info["pinned_hash"] = pinned.hex()
        info["matches_pinned"] = pinned == g.hash
    print(json.dumps(info, indent=2))


def cmd_emission(args):
    rows = reward_mod.emission_table()
    if args.json:
        print(json.dumps([{
            "epoch": e, "start_height": h, "reward_quphi": r,
            "reward_quh": rq, "cumulative_quphi": cum,
            "cumulative_quh": cum / C.QUPHI_PER_QUH,
        } for e, h, r, rq, cum in rows], indent=2))
        return
    print(f"{'epoch':>5} {'start height':>12} {'reward (QUH)':>18} "
          f"{'cumulative (QUH)':>22}")
    for e, h, r, rq, cum in rows:
        print(f"{e:>5} {h:>12} {rq:>18,.8f} {cum / C.QUPHI_PER_QUH:>22,.3f}")
    exact = reward_mod.exact_total_emission()
    print(f"\ncap                {C.MAX_SUPPLY_QUH:,} QUH")
    print(f"exact emission     {exact / C.QUPHI_PER_QUH:,.4f} QUH "
          f"({exact:,} quphi)")
    print(f"below the cap      {(C.MAX_SUPPLY - exact) / C.QUPHI_PER_QUH:.4f} QUH")
    print(f"final reward at    height {reward_mod.last_reward_height():,}")


def cmd_rpc(args):
    from qeuph.wallet.wallet import rpc_call
    net = get_network()
    url = args.url or default_rpc_url(net)
    params = {}
    if args.params:
        try:
            params = json.loads(args.params)
        except Exception:
            params = args.params
    try:
        res = rpc_call(url, args.method, params)
    except Exception as e:
        print(f"RPC error: {e}")
        sys.exit(1)
    print(json.dumps(res, indent=2))


def cmd_address(args):
    from qeuph.crypto import address as addr_mod
    net = _net(args)
    addr = args.target.strip()
    ahash = addr_mod.address_to_hash(addr, net.hrp)
    is_valid = ahash is not None and len(ahash) == C.ADDRESS_HASH_SIZE
    if args.action == "validate":
        print(json.dumps({
            "address": addr, "network": net.name, "hrp": net.hrp,
            "valid": is_valid,
            "addr_hash": ahash.hex() if is_valid else None,
        }, indent=2))
        sys.exit(0 if is_valid else 1)
    if not is_valid:
        sys.exit(f"Invalid {net.hrp} address")
    print(f"Address    {addr}")
    print(f"Network    {net.name} (hrp {net.hrp})")
    print(f"Hash       {ahash.hex()}")
    print(f"Hash bits  {len(ahash) * 8}")
    print(f"Encoding   Bech32m (BIP-350), {len(addr)} characters")
    print("Derivation double SHA3-512(ML-DSA-87 public key)")


def cmd_crypto(args):
    from qeuph.crypto import ml_dsa
    from qeuph.crypto import address as addr_mod
    from qeuph.crypto import fips204
    net = _net(args)
    if args.action == "keygen":
        seed, pk, sk = ml_dsa.generate_keypair()
        addr = addr_mod.pk_to_address(pk, net.hrp)
        print("ML-DSA-87 (FIPS 204) keypair")
        print(f"Master Seed   {seed.hex()}")
        print(f"Public Key    {len(pk)} bytes  {pk.hex()[:64]}...")
        print(f"Secret Key    {len(sk)} bytes  {sk.hex()[:64]}...")
        print(f"Address       {addr}  ({net.hrp}1...)")
    elif args.action == "test":
        print("FIPS 204 ML-DSA-87 roundtrip")
        msg = b"Qeuph post-quantum cryptographic verification"
        seed, pk, sk = ml_dsa.generate_keypair()
        sig = ml_dsa.sign_with_seed(seed, msg)
        valid = ml_dsa.verify(pk, msg, sig)
        tamper = ml_dsa.verify(pk, msg + b"X", sig)
        pure = ml_dsa.verify_pure(pk, msg, sig)
        print(f"Backend            {ml_dsa.backend_name()}")
        print(f"Verify (fast)      {valid}")
        print(f"Verify (reference) {pure}")
        print(f"Tamper detected    {not tamper}")
        if not (valid and pure and not tamper):
            sys.exit(1)
    elif args.action == "info":
        print("FIPS 204 ML-DSA-87 (NIST security category 5)")
        print(f"Backend        {ml_dsa.backend_name()}")
        print(f"Public key     {ml_dsa.PK_SIZE} bytes")
        print(f"Secret key     {ml_dsa.SK_SIZE} bytes")
        print(f"Signature      {ml_dsa.SIG_SIZE} bytes")
        print(f"Seed           {ml_dsa.SEED_SIZE} bytes")
        print(f"q              {fips204.Q}")
        print(f"(k, l)         ({fips204.K}, {fips204.L})")
        print(f"eta, tau       {fips204.ETA}, {fips204.TAU}")
        print(f"gamma1, gamma2 {fips204.GAMMA1}, {fips204.GAMMA2}")
        print(f"omega          {fips204.OMEGA}")
        print("H / G          SHAKE256 / SHAKE128")
        print(f"zetas          512th root of unity = {fips204.ZETA} (verified "
              f"against FIPS 204 Appendix B)")
    elif args.action == "bench":
        import time
        n = 200
        t0 = time.time()
        for _ in range(n):
            ml_dsa.pk_from_seed(os.urandom(32))
        print(f"keygen   {n / (time.time() - t0):8.1f} /s")
        seed = os.urandom(32)
        msg = os.urandom(32)
        t0 = time.time()
        for _ in range(n):
            ml_dsa.sign_with_seed(seed, msg)
        print(f"sign     {n / (time.time() - t0):8.1f} /s")
        pk = ml_dsa.pk_from_seed(seed)
        sig = ml_dsa.sign_with_seed(seed, msg)
        t0 = time.time()
        for _ in range(n):
            ml_dsa.verify(pk, msg, sig)
        print(f"verify   {n / (time.time() - t0):8.1f} /s")
        t0 = time.time()
        for _ in range(20):
            ml_dsa.verify_pure(pk, msg, sig)
        print(f"verify   {20 / (time.time() - t0):8.1f} /s  (pure-Python "
              f"reference)")


def cmd_web(args):
    from qeuph.web.server import serve
    net = _with_data_dir(_net(args), args.data_dir)
    # serve() takes a network NAME; passing the Network object made
    # `qeuph web` exit with "unknown network Network(name='mainnet', ...)",
    # so a documented entry point simply did not start.
    if args.embedded_node == "off" and not args.remote_rpc:
        sys.exit("--embedded-node off requires --remote-rpc URL (the JSON-RPC "
                 "endpoint of the node this UI attaches to)")
    if args.embedded_node != "off" and args.remote_rpc:
        sys.exit("--remote-rpc only applies with --embedded-node off")
    serve(host=args.host, port=args.port, network=net.name,
          data_root=net.data_dir, embedded=args.embedded_node,
          connect_peers=args.connect, p2p_host=args.p2p_host,
          remote_rpc=args.remote_rpc,
          allow_remote=args.allow_remote)


def cmd_preflight(args):
    """Report, without starting anything, whether this build can run.

    Every check is shared with the daemon's own startup warnings, so what an
    operator sees here is exactly what a `qeuph node` on this machine would
    report.  Exit code is 0 when there is no `fail` check.
    """
    from qeuph.main import FAIL, OK, WARN, parse_peer, preflight_report
    net = _with_data_dir(_net(args), args.data_dir)
    peers = [parse_peer(c, net.p2p_port) for c in (args.connect or [])]
    report = preflight_report(
        net, connect_peers=peers, seed_hosts=args.seed or [],
        rpc_host=args.rpc_host, rpc_port=args.rpc_port,
        p2p_port=args.p2p_port or net.p2p_port, data_dir=net.data_dir,
        rpc_authenticated=bool(args.rpc_user and args.rpc_password))
    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0 if report["ok"] else 1)
    print(f"{net.name} preflight  (qeuph {C.VERSION}, protocol "
          f"{C.PROTOCOL_VERSION})")
    for c in report["checks"]:
        print(f"  {c['status']:<4} {c['name']:<12} {c['detail']}")
    counts = {s: sum(1 for c in report["checks"] if c["status"] == s)
              for s in (OK, WARN, FAIL)}
    print(f"\n{counts[OK]} ok, {counts[WARN]} warn, {counts[FAIL]} fail")
    if not report["ok"]:
        print("this configuration cannot run as shipped: fix the failures "
              "above before starting a node")
    sys.exit(0 if report["ok"] else 1)


def cmd_version(args):
    from qeuph import __version__
    from qeuph.crypto import ml_dsa
    from qeuph.config import NETWORKS
    print(f"qeuph {__version__}  (protocol {C.PROTOCOL_VERSION}, "
          f"ml-dsa-87/{ml_dsa.backend_name()})")
    for name, net in NETWORKS.items():
        print(f"  {name:8s} p2p {net.p2p_port:<6d} rpc {net.default_rpc_port:<6d} "
              f"hrp {net.hrp:<5s} genesis {net.genesis_timestamp}")


# ---------------------------------------------------------------------------
def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False) and not args.cmd:
        cmd_version(args)
        return
    handlers = {
        "node": cmd_node, "mine": cmd_mine, "wallet": cmd_wallet,
        "chain": cmd_chain, "rpc": cmd_rpc, "genesis": cmd_genesis,
        "emission": cmd_emission, "address": cmd_address,
        "crypto": cmd_crypto, "web": cmd_web, "version": cmd_version,
        "preflight": cmd_preflight,
    }
    fn = handlers.get(args.cmd)
    if fn is None:
        parser.print_help()
        sys.exit(2)
    try:
        fn(args)
    except (WalletError, ValueError) as e:
        # a user-facing failure, not a crash: report it on stderr and exit 1
        print(f"qeuph {args.cmd}: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()

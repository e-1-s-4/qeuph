"""
Qeuph daemon: wires ChainManager + Mempool + QNode + RPC + Miner together
and runs the asyncio event loop.  Mirrors QRL's main.py/daemon flow.

Startup performs a chain-identity self-check: the rebuilt genesis block must
match the pinned mainnet hash, the data directory must be usable, and the
node reports clearly when it has no peers and no seeds (so an operator can see
immediately that it cannot sync).

Shutdown: SIGINT/SIGTERM or the RPC `stop` method all resolve to the same
stop event; the node's read loops race against it, so shutdown completes
promptly even with silent peers connected.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import time
from typing import List, Optional, Tuple

from qeuph import constants as C
from qeuph.config import Network, bootstrap_nodes, dns_seeds, get_network
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.network.rpc import RPCService
from qeuph.node.node import QNode
from qeuph.services.miner import SoloMiner

logger = logging.getLogger("qeuph.daemon")


def setup_logging(verbose: bool = False, logfile: Optional[str] = None):
    handlers: List[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if logfile:
        os.makedirs(os.path.dirname(os.path.abspath(logfile)) or ".",
                    exist_ok=True)
        handlers.append(logging.FileHandler(logfile))
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers, force=True)


# ---------------------------------------------------------------------------
# Launch readiness ("preflight")
# ---------------------------------------------------------------------------
OK = "ok"
WARN = "warn"
FAIL = "fail"


def _add(report: dict, name: str, status: str, detail: str) -> str:
    report["checks"].append({"name": name, "status": status,
                             "detail": detail})
    return status


def _port_free(host: str, port: int) -> bool:
    """True when nothing owns `host:port` yet.

    Uses the same socket options the real listeners use, because a probe that
    binds with plain SO_REUSEADDR reports "free" on Windows for a port another
    process already owns - the exact mistake this check exists to catch.
    """
    from qeuph.network.listen import listener_socket
    try:
        sock = listener_socket(host or "127.0.0.1", int(port))
        sock.close()
        return True
    except (OSError, ValueError, OverflowError):
        return False


def _read_only_meta(db_path: str, keys) -> dict:
    """Read meta rows out of a stored chain WITHOUT opening it for write.

    Returns {} when the file is missing or is not a usable store, so a
    half-written or foreign chain.db is reported, never crashed on.
    """
    import sqlite3
    from pathlib import Path
    if not os.path.isfile(db_path):
        return {}
    uri = Path(db_path).absolute().as_uri() + "?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=2.0)
    except sqlite3.Error:
        return {}
    try:
        out = {}
        for key in keys:
            row = con.execute("SELECT value FROM meta WHERE key=?",
                              (key,)).fetchone()
            out[key] = row[0] if row else None
        row = con.execute(
            "SELECT hash FROM main_chain WHERE height=0").fetchone()
        out["genesis"] = row[0] if row else None
        return out
    except sqlite3.Error:
        return {}
    finally:
        con.close()


def _genesis_check(report: dict, network: Network) -> None:
    from qeuph.core import genesis as genesis_mod
    from qeuph.config import checkpoint_for
    try:
        g = genesis_mod.build_genesis(network)
    except Exception as e:                      # pragma: no cover - defensive
        _add(report, "genesis", FAIL, f"cannot build genesis: {e}")
        return
    if not g.header.meets_target():
        _add(report, "genesis", FAIL,
             "genesis block does not satisfy its own proof-of-work target")
        return
    if not genesis_mod.validate_genesis(g, network):
        _add(report, "genesis", FAIL,
             "genesis block fails its own validation rules")
        return
    pinned = checkpoint_for(network, 0)
    if pinned is not None and pinned != g.hash:
        _add(report, "genesis", FAIL,
             f"genesis hash {g.hash.hex()[:32]}... does not match the pinned "
             f"checkpoint {pinned.hex()[:32]}...")
        return
    _add(report, "genesis", OK,
         f"{g.hash.hex()[:32]}... (height 0, nonce {g.header.nonce})")


def _crypto_check(report: dict, network: Network) -> None:
    from qeuph.core import pow as pow_mod
    from qeuph.crypto import address as addr_mod
    from qeuph.crypto import ml_dsa
    try:
        seed, pk, sk = ml_dsa.generate_keypair()
        msg = b"qeuph preflight"
        sig = ml_dsa.sign_with_seed(seed, msg)
        if not (ml_dsa.verify(pk, msg, sig)
                and not ml_dsa.verify(pk, msg + b"!", sig)):
            raise RuntimeError("ML-DSA-87 sign/verify self-test failed")
        addr = addr_mod.pk_to_address(pk, network.hrp)
        if not addr.startswith(network.hrp + "1") or \
                addr_mod.address_to_hash(addr, network.hrp) is None:
            raise RuntimeError("address encode/decode self-test failed")
    except Exception as e:
        _add(report, "crypto", FAIL, f"self-test failed: {e}")
        return
    _add(report, "crypto", OK,
         f"ML-DSA-87 via {ml_dsa.backend_name()}; signature "
         f"{ml_dsa.SIG_SIZE} B, address {len(addr)} chars")
    try:
        pow_mod.bits_to_target(network.genesis_bits)
        _add(report, "pow", OK,
             f"compact target {hex(network.genesis_bits)} decodes")
    except ValueError as e:
        _add(report, "pow", FAIL, f"genesis bits do not decode: {e}")


def preflight_report(network: Network, *, connect_peers=None,
                     seed_hosts=None, rpc_host: Optional[str] = None,
                     rpc_port: Optional[int] = None,
                     p2p_port: Optional[int] = None,
                     data_dir: Optional[str] = None,
                     rpc_authenticated: bool = False) -> dict:
    """Readiness report for launching `network`; starts nothing, mines none.

    Returns {"network", "checks": [{name, status, detail}], "ok", "warnings"}
    with status one of "ok" / "warn" / "fail".  "fail" means this build or
    configuration cannot work as shipped; "warn" means it works but the
    operator must know something.  `qeuph preflight` prints it and the daemon
    logs the non-ok lines at startup, so the two can never disagree.
    """
    from qeuph.config import bootstrap_nodes, dns_seeds
    from qeuph.core import genesis as genesis_mod
    from qeuph.core import reward as reward_mod
    report: dict = {"network": network.name, "checks": []}
    _add(report, "build", OK,
         f"qeuph {C.VERSION}, protocol {C.PROTOCOL_VERSION}, "
         f"{network.name} (p2p {p2p_port or network.p2p_port}, "
         f"rpc {rpc_port or network.rpc_port})")
    _genesis_check(report, network)
    _crypto_check(report, network)

    emitted = reward_mod.exact_total_emission()
    if 0 < emitted <= C.MAX_SUPPLY:
        _add(report, "emission", OK,
             f"{emitted / C.QUPHI_PER_QUH:,.4f} QUH over "
             f"{reward_mod.epoch_count()} epochs "
             f"({(C.MAX_SUPPLY - emitted) / C.QUPHI_PER_QUH:.4f} QUH below "
             f"the {C.MAX_SUPPLY_QUH:,} QUH cap)")
    else:
        _add(report, "emission", FAIL,
             f"emission {emitted} is outside 0..{C.MAX_SUPPLY}")

    target_dir = data_dir or network.data_dir
    try:
        os.makedirs(target_dir, exist_ok=True)
        probe = os.path.join(target_dir, ".qeuph-preflight")
        with open(probe, "wb") as fh:
            fh.write(b"qeuph")
        os.remove(probe)
        _add(report, "data dir", OK, f"{target_dir} is writable")
    except OSError as e:
        _add(report, "data dir", FAIL, f"{target_dir} is not writable: {e}")

    db_path = os.path.join(target_dir, "chain.db")
    meta = _read_only_meta(db_path, ("tip", "tip_height"))
    if not meta:
        _add(report, "chain store", OK,
             "no chain.db yet (a fresh data directory is created on start)")
    else:
        height = int.from_bytes(meta.get("tip_height") or b"", "little") \
            if meta.get("tip_height") else 0
        tip = (meta.get("tip") or b"").hex()
        stored_genesis = meta.get("genesis")
        expected = genesis_mod.build_genesis(network).hash
        if stored_genesis is not None and stored_genesis != expected:
            _add(report, "chain store", FAIL,
                 f"{db_path} holds a DIFFERENT chain (genesis "
                 f"{stored_genesis.hex()[:32]}... != {expected.hex()[:32]}...)")
        else:
            _add(report, "chain store", OK,
                 f"{db_path} at height {height} (tip {tip[:32]}...)")

    for label, host, port in (
            ("p2p port", "0.0.0.0", p2p_port or network.p2p_port),
            ("rpc port", rpc_host or C.DEFAULT_RPC_HOST,
             rpc_port or network.rpc_port)):
        if _port_free(host, port):
            _add(report, label, OK, f"{host}:{port} is free")
        else:
            _add(report, label, WARN,
                 f"{host}:{port} is already in use (another node running?)")

    peers = list(connect_peers or []) + list(bootstrap_nodes(network))
    seeds = list(seed_hosts or []) + list(dns_seeds(network))
    if peers or seeds:
        _add(report, "peers", OK,
             f"{len(peers)} bootstrap peer(s), {len(seeds)} DNS seed(s)")
    else:
        _add(report, "peers", WARN,
             "no bootstrap peers and no DNS seeds configured: this node "
             "cannot find the network on its own. Pass --connect host:port "
             "or --seed host, or set qeuph.constants.BOOTSTRAP_NODES_"
             f"{network.name.upper()} / DNS_SEEDS_{network.name.upper()}")

    if network.is_mainnet:
        if len(network.checkpoints) <= 1:
            _add(report, "checkpoints", WARN,
                 f"only the genesis checkpoint is pinned "
                 f"({len(network.checkpoints)}); add periodic block "
                 f"checkpoints to CHECKPOINTS before launch")
        else:
            _add(report, "checkpoints", OK,
                 f"{len(network.checkpoints)} checkpoints pinned")
        if time.time() < C.MAINNET_LAUNCH_TIMESTAMP:
            _add(report, "launch", WARN,
                 "mainnet is not live yet (launch "
                 + time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                 time.gmtime(C.MAINNET_LAUNCH_TIMESTAMP))
                 + ")")
        else:
            _add(report, "launch", OK, "mainnet launch time has passed")
        if rpc_host and rpc_host not in ("127.0.0.1", "::1", "localhost") \
                and not rpc_authenticated:
            _add(report, "rpc auth", WARN,
                 f"RPC is bound to {rpc_host} without --rpc-user/"
                 f"--rpc-password: that is unauthenticated full node control")
        else:
            _add(report, "rpc auth", OK,
                 "RPC is loopback-only or password protected")
    else:
        _add(report, "economics", WARN,
             f"{network.name} carries no economic value; use it for testing")

    report["warnings"] = [f"{c['name']}: {c['detail']}"
                          for c in report["checks"] if c["status"] != OK]
    report["ok"] = not any(c["status"] == FAIL for c in report["checks"])
    return report




class Daemon:
    def __init__(self, network: Optional[Network] = None,
                 mine_to: Optional[str] = None,
                 connect_peers: Optional[List[Tuple[str, int]]] = None,
                 rpc_host: str = C.DEFAULT_RPC_HOST,
                 seed_hosts: Optional[List[str]] = None,
                 rpc_user: Optional[str] = None,
                 rpc_password: Optional[str] = None,
                 miner_threads: int = 1,
                 max_peers: int = 64,
                 p2p_host: str = "0.0.0.0"):
        self.network = network or get_network()
        self.chain = ChainManager(self.network)
        # the state provider keeps the pool correct across reorganisations,
        # which REPLACE the ChainState object
        self.mempool = Mempool(self.chain.state_provider(),
                               height_fn=self.chain.height,
                               mtp_fn=self.chain.median_time_past)
        peers = list(connect_peers or [])
        if not peers:
            peers = [tuple(p) for p in bootstrap_nodes(self.network)]
        self.node = QNode(self.network, self.chain, self.mempool,
                          connect_peers=peers,
                          seed_hosts=list(seed_hosts or []),
                          max_peers=max_peers,
                          bind_host=p2p_host)
        self.miner = SoloMiner(self.node, threads=miner_threads)
        self.rpc = RPCService(self.node, self.miner, rpc_host,
                              self.network.rpc_port,
                              lambda: self._stop_evt,
                              rpc_user=rpc_user, rpc_password=rpc_password)
        self._stop_evt = asyncio.Event()
        self._mine_to = mine_to
        self.started_at = time.time()
        # reorg hook: revive mempool txs from the disconnected chain
        self.chain.on_reorg = self.node.reorg_callback

    # ------------------------------------------------------------------
    def preflight(self) -> List[str]:
        """Consistency checks run before the listeners come up.  Returns a
        list of human-readable warnings (empty when everything is fine).

        The checks themselves live in `preflight_report`, which is also what
        `qeuph preflight` prints, so the daemon's startup warnings and the
        operator-facing report can never disagree.  Only the facts the daemon
        owns (its ports, its peer list, its RPC host) are added here.
        """
        report = preflight_report(
            self.network,
            connect_peers=self.node.connect_peers,
            seed_hosts=self.node.seed_hosts,
            rpc_host=self.rpc.host,
            rpc_port=self.rpc.port,
            p2p_port=self.network.p2p_port,
            data_dir=self.network.data_dir,
            rpc_authenticated=self.rpc.auth_required)
        return list(report["warnings"])

    async def run(self):
        loop = asyncio.get_running_loop()
        for w in self.preflight():
            logger.warning("preflight: %s", w)
        self.miner.attach_loop(loop)
        await self.node.start()
        self.rpc.start_background(loop)
        logger.info("qeuph %s (%s) | network=%s height=%d tip=%s",
                    C.VERSION, self._crypto_backend(), self.network.name,
                    self.chain.height(), self.chain.tip_hash().hex()[:16])
        logger.info("genesis %s", self.chain.genesis.hash.hex())
        logger.info("p2p %s:%d | rpc %s (auth=%s) | data %s",
                    self.node.bind_host, self.network.p2p_port, self.rpc.url,
                    "yes" if self.rpc.auth_required else "no",
                    self.network.data_dir)
        # signal handlers for graceful shutdown
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._request_stop)
            except (NotImplementedError, RuntimeError):
                pass
        if self._mine_to:
            from qeuph.crypto import address as addr_mod
            ahash = addr_mod.address_to_hash(self._mine_to, self.network.hrp)
            if ahash is None:
                raise SystemExit(
                    f"invalid payout address for {self.network.name}: "
                    f"{self._mine_to}")
            self.miner.set_payout(ahash)
            self.miner.start()
            logger.info("solo mining to %s with %d thread(s)",
                        self._mine_to, self.miner.threads)
        # idle until stopped
        await self._stop_evt.wait()
        logger.info("shutting down")
        try:
            await asyncio.wait_for(self.node.stop(), timeout=15.0)
        except asyncio.TimeoutError:
            logger.warning("node stop timed out")
        self.rpc.stop()
        self.miner.stop()
        self.chain.close()
        logger.info("stopped cleanly after %.1fs",
                    time.time() - self.started_at)

    def _request_stop(self):
        logger.info("stop requested")
        self._stop_evt.set()

    @staticmethod
    def _crypto_backend() -> str:
        from qeuph.crypto import ml_dsa
        return f"ml-dsa-87/{ml_dsa.backend_name()}"


def parse_peer(spec: str, default_port: int) -> Tuple[str, int]:
    host, _, port = spec.rpartition(":")
    if not host:
        host, port = spec, str(default_port)
    try:
        return host, int(port)
    except ValueError:
        raise SystemExit(f"bad peer specification {spec!r} (expected host:port)")


def run_daemon(network_name=None, mine_to: Optional[str] = None,
               connect: Optional[List[str]] = None,
               rpc_host: str = C.DEFAULT_RPC_HOST,
               seed_hosts: Optional[List[str]] = None,
               rpc_user: Optional[str] = None,
               rpc_password: Optional[str] = None,
               miner_threads: int = 1,
               verbose: bool = False,
               logfile: Optional[str] = None,
               p2p_host: str = "0.0.0.0"):
    setup_logging(verbose, logfile)
    # accept either a network name or a pre-configured Network object
    # (the CLI overrides ports/data_dir on the object before starting)
    net = network_name if isinstance(network_name, Network) else get_network(network_name)
    peers = [parse_peer(c, net.p2p_port) for c in (connect or [])]
    seeds = list(seed_hosts if seed_hosts is not None
                 else dns_seeds(net))
    if rpc_host not in ("127.0.0.1", "::1", "localhost") and \
            not (rpc_user and rpc_password):
        logger.warning("RPC on %s without --rpc-user/--rpc-password exposes "
                       "full node control (mining, submission, stop)", rpc_host)
    d = Daemon(net, mine_to=mine_to, connect_peers=peers, rpc_host=rpc_host,
               seed_hosts=seeds, rpc_user=rpc_user, rpc_password=rpc_password,
               miner_threads=miner_threads, p2p_host=p2p_host)
    try:
        asyncio.run(d.run())
    except OSError as e:
        from qeuph.network.listen import port_busy
        if port_busy(e):
            # The listeners bind exclusively on Windows and a busy port is
            # the one startup failure an operator hits routinely; say exactly
            # which port and what to do instead of a traceback.
            logger.error("could not bind %s:%d (%s)", net.p2p_port,
                         net.rpc_port, e)
            raise SystemExit(
                f"a port Qeuph needs is already in use ({e}). Pass "
                f"--p2p-port/--rpc-port to choose free ports, or stop the "
                f"other node.")
        raise
    except KeyboardInterrupt:
        pass

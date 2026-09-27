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


class Daemon:
    def __init__(self, network: Optional[Network] = None,
                 mine_to: Optional[str] = None,
                 connect_peers: Optional[List[Tuple[str, int]]] = None,
                 rpc_host: str = C.DEFAULT_RPC_HOST,
                 seed_hosts: Optional[List[str]] = None,
                 rpc_user: Optional[str] = None,
                 rpc_password: Optional[str] = None,
                 miner_threads: int = 1,
                 max_peers: int = 64):
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
                          max_peers=max_peers)
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
        list of human-readable warnings (empty when everything is fine)."""
        warnings: List[str] = []
        g = self.chain.genesis
        if self.network.is_mainnet and g.hash != C.CHECKPOINTS.get(0):
            warnings.append(
                "mainnet genesis hash does not match the pinned checkpoint - "
                "the build is inconsistent with the released chain identity")
        if not self.chain.genesis.header.meets_target():
            warnings.append("genesis block does not satisfy its own PoW target")
        if self.network.is_mainnet and \
                time.time() < C.MAINNET_LAUNCH_TIMESTAMP:
            warnings.append(
                f"mainnet is not live yet "
                f"(launch {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(C.MAINNET_LAUNCH_TIMESTAMP))})")
        if not os.path.isdir(self.network.data_dir):
            warnings.append(f"data directory {self.network.data_dir} is missing")
        if not self.node.connect_peers and not self.node.seed_hosts:
            if self.network.is_mainnet:
                warnings.append(
                    "no bootstrap peers and no DNS seeds configured: this node "
                    "cannot find the network on its own. Pass --connect "
                    "host:port, or --seed host, or set "
                    "qeuph.constants.BOOTSTRAP_NODES_MAINNET / "
                    "DNS_SEEDS_MAINNET before mainnet launch")
            else:
                warnings.append(
                    "no bootstrap peers and no DNS seeds configured: peers must "
                    "be supplied with --connect host:port or --seed host")
        if self.network.is_regtest:
            warnings.append("regtest: instant mining, no economic value")
        if self.network.is_testnet:
            warnings.append("testnet: no economic value")
        return warnings

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
        logger.info("p2p %d | rpc %s (auth=%s) | data %s",
                    self.network.p2p_port, self.rpc.url,
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
               logfile: Optional[str] = None):
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
               miner_threads=miner_threads)
    try:
        asyncio.run(d.run())
    except KeyboardInterrupt:
        pass

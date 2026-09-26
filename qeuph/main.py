"""
Qeuph daemon: wires ChainManager + Mempool + QNode + RPC + Miner together
and runs the asyncio event loop.  Mirrors QRL's main.py/daemon flow.

Shutdown: SIGINT/SIGTERM or the RPC `stop` method all resolve to the same
stop event; the node's read loops race against it, so shutdown completes
promptly even with silent peers connected.
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
from typing import List, Optional, Tuple

from qeuph import constants as C
from qeuph.config import Network, get_network
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.network.rpc import RPCService
from qeuph.node.node import QNode
from qeuph.services.miner import SoloMiner

logger = logging.getLogger("qeuph.daemon")


class Daemon:
    def __init__(self, network: Optional[Network] = None,
                 mine_to: Optional[str] = None,
                 connect_peers: Optional[List[Tuple[str, int]]] = None,
                 rpc_host: str = C.DEFAULT_RPC_HOST,
                 seed_hosts: Optional[List[str]] = None):
        self.network = network or get_network()
        self.chain = ChainManager(self.network)
        self.mempool = Mempool(self.chain.state, height_fn=self.chain.height,
                               mtp_fn=self.chain.median_time_past)
        self.node = QNode(self.network, self.chain, self.mempool,
                          connect_peers=connect_peers or [],
                          seed_hosts=seed_hosts or [])
        self.miner = SoloMiner(self.node)
        self.rpc = RPCService(self.node, self.miner, rpc_host,
                              self.network.rpc_port, lambda: self._stop_evt)
        self._stop_evt = asyncio.Event()
        self._mine_to = mine_to
        # reorg hook: revive mempool txs from the disconnected chain
        self.chain.on_reorg = self.node.reorg_callback

    async def run(self):
        loop = asyncio.get_running_loop()
        self.miner.attach_loop(loop)
        await self.node.start()
        self.rpc.start_background(loop)
        logger.info("qeuph %s (%s backend) | network=%s height=%d tip=%s",
                    C.VERSION, self._crypto_backend(), self.network.name,
                    self.chain.height(), self.chain.tip_hash().hex()[:16])
        logger.info("p2p %d | rpc %s:%d", self.network.p2p_port,
                    self.rpc.host, self.rpc.port)
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
                raise SystemExit(f"invalid payout address for {self.network.name}")
            self.miner.set_payout(ahash)
            self.miner.start()
            logger.info("solo mining to %s", self._mine_to)
        # idle until stopped
        await self._stop_evt.wait()
        logger.info("shutting down")
        try:
            await asyncio.wait_for(self.node.stop(), timeout=15.0)
        except asyncio.TimeoutError:
            logger.warning("node stop timed out")
        self.rpc.stop()
        self.miner.stop()
        if self.chain.store:
            self.chain.store.close()
        logger.info("stopped")

    def _request_stop(self):
        logger.info("stop requested")
        self._stop_evt.set()

    @staticmethod
    def _crypto_backend() -> str:
        from qeuph.crypto import ml_dsa
        return f"ml-dsa-87/{ml_dsa.backend_name()}"


def run_daemon(network_name=None, mine_to: Optional[str] = None,
               connect: Optional[List[str]] = None, rpc_host: str = C.DEFAULT_RPC_HOST,
               seed_hosts: Optional[List[str]] = None):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    # accept either a network name or a pre-configured Network object
    # (the CLI overrides ports/data_dir on the object before starting)
    net = network_name if isinstance(network_name, Network) else get_network(network_name)
    peers = []
    for c in (connect or []):
        host, _, port = c.partition(":")
        peers.append((host, int(port or net.p2p_port)))
    seeds = list(seed_hosts if seed_hosts is not None else
                 (C.DNS_SEEDS_MAINNET if net.is_mainnet else C.DNS_SEEDS_TESTNET))
    d = Daemon(net, mine_to=mine_to, connect_peers=peers, rpc_host=rpc_host,
               seed_hosts=seeds)
    asyncio.run(d.run())

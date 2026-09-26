"""
Qeuph daemon: wires ChainManager + Mempool + QNode + RPC + Miner together
and runs the asyncio event loop.  Mirrors QRL's main.py/daemon flow.
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
                 rpc_host: str = C.DEFAULT_RPC_HOST):
        self.network = network or get_network()
        self.chain = ChainManager(self.network)
        self.mempool = Mempool(self.chain.state, height_fn=self.chain.height)
        self.node = QNode(self.network, self.chain, self.mempool,
                          connect_peers=connect_peers or [])
        self.miner = SoloMiner(self.node)
        self.rpc = RPCService(self.node, self.miner, rpc_host,
                              self.network.rpc_port, lambda: self._stop_evt)
        self._stop_evt = asyncio.Event()
        self._mine_to = mine_to

    async def run(self):
        loop = asyncio.get_running_loop()
        self.miner.attach_loop(loop)
        await self.node.start()
        self.rpc.start_background(loop)
        logger.info("qeuph %s | height=%d tip=%s", self.network.name,
                    self.chain.height(), self.chain.tip_hash().hex()[:16])
        logger.info("rpc listening on %s:%d", self.rpc.host, self.rpc.port)
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
        await self.node.stop()
        self.rpc.stop()
        self.miner.stop()
        if self.chain.store:
            self.chain.store.close()


def run_daemon(network_name: Optional[str] = None, mine_to: Optional[str] = None,
               connect: Optional[List[str]] = None, rpc_host: str = C.DEFAULT_RPC_HOST):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    net = get_network(network_name)
    peers = []
    for c in (connect or []):
        host, _, port = c.partition(":")
        peers.append((host, int(port or net.p2p_port)))
    d = Daemon(net, mine_to=mine_to, connect_peers=peers, rpc_host=rpc_host)
    asyncio.run(d.run())

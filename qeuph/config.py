"""
Network profiles: mainnet, testnet, regtest.

Modeled on QRL's DevConfig/user config split, simplified to a dataclass of
overridable parameters.  Regtest exists for the integration test suite:
tiny difficulty so blocks can be mined in milliseconds.
"""
from __future__ import annotations

import dataclasses
import os
from typing import Optional

from qeuph import constants as C


@dataclasses.dataclass
class Network:
    name: str
    hrp: str
    p2p_port: int
    rpc_port: int
    genesis_bits: int
    retarget_interval: int
    block_time: int
    genesis_timestamp: int
    genesis_message: str
    magic: bytes
    data_dir: str

    @property
    def is_mainnet(self) -> bool:
        return self.name == "mainnet"


MAINNET = Network(
    name="mainnet",
    hrp=C.ADDRESS_HRP_MAINNET,
    p2p_port=C.DEFAULT_P2P_PORT,
    rpc_port=C.DEFAULT_RPC_PORT,
    genesis_bits=C.GENESIS_BITS,
    retarget_interval=C.RETARGET_INTERVAL,
    block_time=C.BLOCK_TIME_SECONDS,
    genesis_timestamp=C.GENESIS_TIMESTAMP,
    genesis_message=C.GENESIS_MESSAGE,
    magic=C.MAGIC_BYTES,
    data_dir=os.path.expanduser("~/.qeuph"),
)

TESTNET = dataclasses.replace(
    MAINNET,
    name="testnet",
    hrp=C.ADDRESS_HRP_TESTNET,
    p2p_port=29090,
    rpc_port=29091,
    genesis_timestamp=1780000000,
    data_dir=os.path.expanduser("~/.qeuph-testnet"),
)

# Regtest: no retarget, near-instant mining (target ~2^511, p ~ 1/2 per hash)
REGTEST = dataclasses.replace(
    MAINNET,
    name="regtest",
    hrp=C.ADDRESS_HRP_REGTEST,
    p2p_port=39090,
    rpc_port=39091,
    genesis_bits=0x407FFFFF,
    retarget_interval=2**30,        # effectively never
    genesis_timestamp=1,
    data_dir=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          ".regtest"),
)

NETWORKS = {"mainnet": MAINNET, "testnet": TESTNET, "regtest": REGTEST}


def get_network(name: Optional[str] = None) -> Network:
    if name is None:
        name = os.environ.get("QEUPH_NETWORK", "mainnet")
    try:
        return NETWORKS[name]
    except KeyError:
        raise ValueError(f"unknown network {name!r}; choose one of {sorted(NETWORKS)}")

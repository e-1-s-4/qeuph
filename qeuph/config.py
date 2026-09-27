"""
Network profiles: mainnet, testnet, regtest.

Modeled on QRL's DevConfig/user config split, simplified to a dataclass of
overridable parameters.  Regtest exists for the integration test suite:
tiny difficulty so blocks can be mined in milliseconds.

The three profiles are module-level singletons and MUST be treated as
immutable: callers that need a customised profile use `dataclasses.replace`
so a global can never be mutated out from under another component.
"""
from __future__ import annotations

import dataclasses
import os
from typing import Optional

from qeuph import constants as C


@dataclasses.dataclass(frozen=True)
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
    default_rpc_port: int = 0
    checkpoints: tuple = ()

    @property
    def is_mainnet(self) -> bool:
        return self.name == "mainnet"

    @property
    def is_regtest(self) -> bool:
        return self.name == "regtest"

    @property
    def is_testnet(self) -> bool:
        return self.name == "testnet"

    def with_(self, **kwargs) -> "Network":
        """Return a copy with overrides applied (never mutates in place)."""
        return dataclasses.replace(self, **kwargs)

    def path(self, *parts: str) -> str:
        return os.path.join(self.data_dir, *parts)


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
    default_rpc_port=C.DEFAULT_RPC_PORT,
    checkpoints=tuple(C.CHECKPOINTS.items()),
)

TESTNET = dataclasses.replace(
    MAINNET,
    name="testnet",
    hrp=C.ADDRESS_HRP_TESTNET,
    p2p_port=29090,
    rpc_port=29091,
    genesis_bits=0x3F0FFFFF,
    genesis_timestamp=1780000000,
    data_dir=os.path.expanduser("~/.qeuph-testnet"),
    magic=C.TESTNET_MAGIC_BYTES,
    default_rpc_port=29091,
    checkpoints=(),
)

# Regtest: no retarget, near-instant mining (target ~2^511, p ~ 1/2 per hash).
# The data directory lives under the user's home so that running regtest
# never writes into a source checkout.
REGTEST = dataclasses.replace(
    MAINNET,
    name="regtest",
    hrp=C.ADDRESS_HRP_REGTEST,
    p2p_port=39090,
    rpc_port=39091,
    genesis_bits=0x407FFFFF,
    retarget_interval=2 ** 30,        # effectively never
    genesis_timestamp=1,
    data_dir=os.path.expanduser("~/.qeuph-regtest"),
    magic=C.REGTEST_MAGIC_BYTES,
    default_rpc_port=39091,
    checkpoints=(),
)

NETWORKS = {"mainnet": MAINNET, "testnet": TESTNET, "regtest": REGTEST}


def get_network(name: Optional[str] = None) -> Network:
    if name is None:
        name = os.environ.get("QEUPH_NETWORK", "mainnet")
    try:
        return NETWORKS[name]
    except KeyError:
        raise ValueError(f"unknown network {name!r}; choose one of {sorted(NETWORKS)}")


def bootstrap_nodes(network: Network):
    if network.is_mainnet:
        return list(C.BOOTSTRAP_NODES_MAINNET)
    if network.is_testnet:
        return list(C.BOOTSTRAP_NODES_TESTNET)
    return []


def dns_seeds(network: Network):
    if network.is_mainnet:
        return list(C.DNS_SEEDS_MAINNET)
    if network.is_testnet:
        return list(C.DNS_SEEDS_TESTNET)
    return []


def checkpoint_for(network: Network, height: int) -> Optional[bytes]:
    """Pinned block hash for `height` on this network (None when unpinned)."""
    if network.is_mainnet:
        return C.CHECKPOINTS.get(height)
    return None


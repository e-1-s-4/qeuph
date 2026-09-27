"""Test fixtures and helpers shared by the Qeuph suite."""
from __future__ import annotations

import os
import shutil

import pytest

from qeuph.config import REGTEST
from qeuph.core.chain import ChainManager
from qeuph.core.mempool import Mempool
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa


@pytest.fixture()
def net(tmp_path):
    """A throwaway regtest network profile with its own data directory."""
    return REGTEST.with_(data_dir=str(tmp_path / "chain"))


@pytest.fixture()
def miner_keys():
    seed, pk, _ = ml_dsa.generate_keypair()
    return seed, pk, addr_mod.pk_to_hash(pk)


def mine(cm: ChainManager, payout_hash: bytes, txs=None, n: int = 1):
    """Mine `n` blocks paying `payout_hash`, returning them oldest-first."""
    out = []
    for i in range(n):
        b, _ = cm.create_block_template(payout_hash, list(txs or []),
                                        timestamp=cm.tip.header.timestamp + 1,
                                        extra_nonce=b"test")
        b.mine()
        cm.connect_block(b, current_time=b.header.timestamp)
        out.append(b)
    return out


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_wallet(hrp: str = "rquh", network: str = "regtest"):
    from qeuph.wallet import Wallet
    return Wallet.create(hrp=hrp, network=network)


def rpc_call(url, method, params=None, timeout=60):
    from qeuph.wallet.wallet import rpc_call as call
    return call(url, method, params or {}, timeout=timeout)


__all__ = ["net", "miner_keys", "mine", "free_port", "make_wallet",
           "rpc_call", "ChainManager", "Mempool", "addr_mod", "ml_dsa",
           "shutil", "os"]

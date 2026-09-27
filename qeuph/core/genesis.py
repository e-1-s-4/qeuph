"""
Genesis block construction (mainnet-ready).

The mainnet genesis embeds the whitepaper's founding message in its
coinbase data, uses the fixed launch timestamp (2026-10-01 00:00:00 UTC)
and is mined once here with the initial difficulty; the winning nonce is
deterministic, so every node reconstructs the identical block.

The coinbase output pays 0 quphi to the null address (hash of the empty
string), mirroring Bitcoin's unspendable genesis reward.  Nothing from
the genesis coinbase can ever be spent.
"""
from __future__ import annotations

from typing import Optional

from qeuph import constants as C
from qeuph.config import Network
from qeuph.core import pow as pow_mod
from qeuph.core.block import Block, BlockHeader
from qeuph.core.merkle import merkle_root
from qeuph.core.tx import Transaction, TxIn, TxOut
from qeuph.crypto.address import dhash

# The one-and-only null recipient: double SHA3-512 of the empty byte string.
NULL_ADDR_HASH = dhash(b"")

# Pinned mainnet genesis PoW nonce (mined 2026-09-26 at bits 0x3D0FFFFF,
# ~0.91 MH/s over 407 s).  Every node rebuilds the identical block from
# this constant, so no node ever needs to mine genesis at startup.
MAINNET_GENESIS_NONCE = 355026620
TESTNET_GENESIS_NONCE = 25
REGTEST_GENESIS_NONCE = 0

MAINNET_GENESIS_HASH = bytes.fromhex(
    "0000000d2f105b239cd085e9d4bd7fa087dc6a085ee37b3842d539ab9c974247"
    "fa8c4000695807b0a5d306d40c713e32b130387f72b64a00bf2b0c9953b179b1")


def build_genesis(network: Network, mine: bool = True,
                  nonce: Optional[int] = None) -> Block:
    """Assemble (and mine) the genesis block for a network.

    For mainnet, testnet, and regtest the pinned winning nonce is used by default,
    so the block is always deterministic and satisfies difficulty without re-mining.
    """
    if nonce is None:
        if network.name == "mainnet":
            nonce = MAINNET_GENESIS_NONCE
        elif network.name == "testnet":
            nonce = TESTNET_GENESIS_NONCE
        elif network.name == "regtest":
            nonce = REGTEST_GENESIS_NONCE
    from qeuph.core.tx import ZERO_TXID, COINBASE_INDEX, MAX_COINBASE_DATA
    msg = network.genesis_message.encode()
    if len(msg) > MAX_COINBASE_DATA:
        raise ValueError("genesis message too long")
    coinbase = Transaction(
        [TxIn(ZERO_TXID, COINBASE_INDEX, 0, data=msg)],
        [TxOut(0, NULL_ADDR_HASH)],
    )
    root = merkle_root([coinbase.txid()])
    header = BlockHeader(
        version=C.BLOCK_VERSION,
        prev_hash=bytes(64),
        merkle_root=root,
        timestamp=network.genesis_timestamp,
        bits=network.genesis_bits,
        height=0,
        nonce=0,
    )
    block = Block(header, [coinbase])
    if mine:
        header.nonce = (pow_mod.mine_header(header.serialize(), header.bits,
                                            max_attempts=1 << 26)
                        if nonce is None else nonce)
    elif nonce is not None:
        header.nonce = nonce
    return block


def genesis_hash(network: Network) -> bytes:
    """Deterministic genesis hash (rebuilds the block)."""
    return build_genesis(network).hash


def validate_genesis(block: Block, network: Network) -> bool:
    hdr = block.header
    if hdr.height != 0:
        return False
    if hdr.prev_hash != bytes(64):
        return False
    if hdr.timestamp != network.genesis_timestamp:
        return False
    if not pow_mod.check_pow(hdr.serialize(), hdr.bits):
        return False
    if len(block.transactions) != 1 or not block.transactions[0].is_coinbase:
        return False
    cb = block.transactions[0]
    if cb.inputs[0].data != network.genesis_message.encode():
        return False
    if cb.total_out != 0:
        return False
    return True

"""Mine the Qeuph mainnet genesis block and print the winning nonce.

The resulting nonce is deterministic evidence that the genesis block
satisfies mainnet initial difficulty (bits 0x3D0FFFFF) and is embedded
into qeuph/core/genesis.py so every node reconstructs the identical block.
"""
import multiprocessing as mp
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qeuph.config import MAINNET
from qeuph.core import pow as pow_mod
from qeuph.core import genesis as genesis_mod
from qeuph.core.block import BlockHeader

BITS = MAINNET.genesis_bits
TARGET = pow_mod.bits_to_target(BITS)


def search(args):
    start, count = args
    from qeuph.core.tx import Transaction, TxIn, TxOut, ZERO_TXID, COINBASE_INDEX
    from qeuph.core.merkle import merkle_root
    net = MAINNET
    msg = net.genesis_message.encode()
    coinbase = Transaction(
        [TxIn(ZERO_TXID, COINBASE_INDEX, 0, data=msg)],
        [TxOut(0, genesis_mod.NULL_ADDR_HASH)],
    )
    root = merkle_root([coinbase.txid()])
    hdr = BlockHeader(1, bytes(64), root, net.genesis_timestamp, BITS, 0, 0)
    # the shared PoW kernel: same code path the node validates with
    for nonce, _tried in pow_mod.mine_range_count(hdr.serialize(), BITS,
                                                 start, count):
        return nonce
    return None


def main():
    procs = max(1, mp.cpu_count())
    chunk = 1 << 24
    print(f"mining genesis at bits {hex(BITS)} "
          f"(target ~2^{TARGET.bit_length()}) with {procs} workers")
    t0 = time.time()
    with mp.Pool(procs) as pool:
        for round_no in range(64):
            jobs = [((round_no * procs + w) * chunk, chunk) for w in range(procs)]
            for res in pool.imap_unordered(search, jobs):
                if res is not None:
                    dt = time.time() - t0
                    print(f"FOUND nonce={res} in {dt:.1f}s "
                          f"({(round_no + 1) * procs * chunk / dt / 1e6:.2f} MH/s)")
                    g = genesis_mod.build_genesis(MAINNET, mine=False, nonce=res)
                    assert pow_mod.check_pow(g.header.serialize(), BITS)
                    print("genesis hash:", g.hash.hex())
                    print("merkle root :", g.header.merkle_root.hex())
                    print("nonce validated against mainnet bits: OK")
                    return res
            print(f"  round {round_no}: {(round_no + 1) * procs * chunk / 1e6:.0f} MH done")
    raise SystemExit("genesis not found in budget")


if __name__ == "__main__":
    main()

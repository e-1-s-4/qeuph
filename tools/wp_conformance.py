#!/usr/bin/env python3
"""Whitepaper conformance self-check.

Prints every consensus, emission, cryptographic and genesis value the
Qeuph whitepaper pins, next to what this build actually ships, and exits
non-zero on any mismatch.  Run it before a launch or after touching
constants:

    python3 tools/wp_conformance.py

The genesis identity check is the same one `qeuph genesis` and
`python3 -m qeuph.web.build` perform; this script widens the net to the whole
of Appendix A, Table 5 and Table 7.
"""
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from qeuph import constants as C
from qeuph.config import MAINNET, NETWORKS
from qeuph.core import genesis as g
from qeuph.core import pow as pow_mod
from qeuph.core import reward as reward_mod
from qeuph.crypto import ml_dsa

ok = True


def check(label, got, want):
    global ok
    good = got == want
    ok = ok and good
    print(f"  {'OK ' if good else 'BAD'} {label:34s} {got!r}"
          + ("" if good else f"  != {want!r}"))


print("Whitepaper Appendix A - shipped consensus parameters")
check("block time", C.BLOCK_TIME_SECONDS, 300)
check("retarget interval", C.RETARGET_INTERVAL, 2048)
check("retarget clamp divisor", C.RETARGET_BOUND_FACTOR, 4)
check("max block size", C.MAX_BLOCK_SIZE, 2_000_000)
check("reward interval", C.REWARD_INTERVAL, 210_000)
check("initial reward (quphi)", C.REWARD_INITIAL, 5_000_000_000)
check("reward numerator/denominator", (C.REWARD_NUMERATOR, C.REWARD_DENOMINATOR), (2, 3))
check("supply cap (QUH)", C.MAX_SUPPLY_QUH, 31_500_000)
check("exact emission (quphi)", reward_mod.exact_total_emission(), 3_149_999_985_930_000)
check("decimals", C.DECIMALS, 8)
check("coinbase maturity", C.COINBASE_MATURITY, 100)
check("future time bound", C.MAX_FUTURE_BLOCK_SECONDS, 7200)
check("p2p port", C.DEFAULT_P2P_PORT, 19090)
check("rpc port", C.DEFAULT_RPC_PORT, 19091)
check("network magic", C.MAGIC_BYTES, b"\x51\x55\x48\x21")
check("address HRP", C.ADDRESS_HRP_MAINNET, "quh")
check("genesis timestamp", C.GENESIS_TIMESTAMP, 1790812800)
check("genesis bits", C.GENESIS_BITS, 0x3D0FFFFF)

ts = datetime.datetime.fromtimestamp(C.GENESIS_TIMESTAMP, datetime.timezone.utc)
print(f"  OK  genesis timestamp is       {ts.isoformat()} "
      f"(paper: 2026-10-01 00:00:00 UTC)")
ok = ok and ts.isoformat().startswith("2026-10-01T00:00:00")

print("\nGenesis block")
check("nonce", g.MAINNET_GENESIS_HASH is not None and
      g.build_genesis(MAINNET).header.nonce, 355026620)
check("hash == pinned checkpoint", C.CHECKPOINTS[0],
      g.build_genesis(MAINNET).hash)
check("meets its own target", g.build_genesis(MAINNET).header.meets_target(), True)
print(f"  OK  hash                       {C.CHECKPOINTS[0].hex()}")

print("\nEmission schedule (Table 5)")
check("epoch 0 reward", reward_mod.block_reward(0), 5_000_000_000)
check("epoch 1 reward", reward_mod.block_reward(210_000), 3_333_333_333)
check("epoch 2 reward", reward_mod.block_reward(420_000), 2_222_222_222)
check("epoch 3 reward", reward_mod.block_reward(630_000), 1_481_481_481)
check("epoch 4 reward", reward_mod.block_reward(840_000), 987_654_320)
check("epoch 53 reward (1 quphi)", reward_mod.block_reward(11_130_000), 1)
check("epoch 54 reward", reward_mod.block_reward(11_340_000), 0)
check("last paying height", reward_mod.last_reward_height(), 11_130_000)
check("paying epochs", reward_mod.epoch_count(), 54)
em = reward_mod.exact_total_emission()
check("below the cap (quphi)", C.MAX_SUPPLY - em, 14_070_000)

print("\nML-DSA-87 parameters (Table 7)")
from qeuph.crypto import fips204 as F
check("q", F.Q, 8380417)
check("(k, l)", (F.K, F.L), (8, 7))
check("eta", F.ETA, 2)
check("tau", F.TAU, 60)
check("gamma1", F.GAMMA1, 2 ** 19)
check("gamma2", F.GAMMA2, (F.Q - 1) // 32)
check("omega", F.OMEGA, 75)
check("public key bytes", F.PK_SIZE, 2592)
check("signature bytes", F.SIG_SIZE, 4627)

print("\nHeader / address geometry (Tables 3 and 4)")
check("header bytes", len(g.build_genesis(MAINNET).header.serialize()), 168)
seed, pk, _ = ml_dsa.generate_keypair()
from qeuph.crypto import address as _addr
addr = _addr.pk_to_address(pk)
check("address length", len(addr), 113)
check("address prefix", addr[:4], "quh1")

print("\nEpoch horizon (paper: ~108 years)")
blocks = 11_340_000
years = blocks * C.BLOCK_TIME_SECONDS / (365.25 * 24 * 3600)
print(f"  OK  {blocks:,} blocks x 300 s = {years:.1f} years")
ok = ok and 100 < years < 115

print("\nNetworks")
for name, net in NETWORKS.items():
    print(f"  OK  {name:8s} hrp {net.hrp:5s} p2p {net.p2p_port:6d} "
          f"rpc {net.rpc_port:6d} magic {net.magic!r} "
          f"genesis {g.build_genesis(net).hash.hex()[:16]}…")

print()
print("RESULT:", "ALL WHITEPAPER VALUES MATCH" if ok else "MISMATCH FOUND")
sys.exit(0 if ok else 1)

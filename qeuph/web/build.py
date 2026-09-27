"""Build / self-check: verify the installed package and the pinned chain identity.

Run with `python3 -m qeuph.web.build` (also wired to `npm run build`).
Every check is an assertion, so a non-zero exit means the tree is not
mainnet-consistent.
"""
from __future__ import annotations

import importlib
import os
import sys

MODULES = [
    "qeuph.constants", "qeuph.config",
    "qeuph.crypto.fips204", "qeuph.crypto.ml_dsa", "qeuph.crypto.bech32m",
    "qeuph.crypto.address",
    "qeuph.core.block", "qeuph.core.chain", "qeuph.core.difficulty",
    "qeuph.core.genesis", "qeuph.core.mempool", "qeuph.core.merkle",
    "qeuph.core.pow", "qeuph.core.reward", "qeuph.core.state",
    "qeuph.core.tx", "qeuph.core.validation",
    "qeuph.db.store",
    "qeuph.network.protocol", "qeuph.network.rpc",
    "qeuph.node.node", "qeuph.services.miner",
    "qeuph.wallet.keys", "qeuph.wallet.keystore", "qeuph.wallet.mnemonic",
    "qeuph.wallet.wallet",
    "qeuph.cli.main", "qeuph.main",
    "qeuph.web.server", "qeuph.web.build",
]


def main() -> int:
    print("Qeuph build self-check")
    print("=" * 62)
    for name in MODULES:
        importlib.import_module(name)
    print(f"modules          {len(MODULES)} imported")

    from qeuph import constants as C
    from qeuph.config import MAINNET, NETWORKS
    from qeuph.core import genesis as genesis_mod
    from qeuph.core import pow as pow_mod
    from qeuph.core import reward as reward_mod
    from qeuph.crypto import ml_dsa
    import qeuph

    if qeuph.__version__ != C.VERSION:
        raise SystemExit(f"version mismatch: {qeuph.__version__} != {C.VERSION}")
    print(f"version          {qeuph.__version__} (protocol {C.PROTOCOL_VERSION})")

    g = genesis_mod.build_genesis(MAINNET)
    assert g.hash == genesis_mod.MAINNET_GENESIS_HASH, "mainnet genesis hash"
    assert g.hash == C.CHECKPOINTS[0], "pinned checkpoint"
    assert genesis_mod.validate_genesis(g, MAINNET), "genesis validity"
    assert g.header.meets_target(), "genesis PoW"
    print(f"mainnet genesis  {g.hash.hex()}")
    print(f"                 nonce {g.header.nonce}, bits {hex(g.header.bits)}, "
          f"difficulty {pow_mod.difficulty_from_bits(g.header.bits):.1f}")

    for name, net in NETWORKS.items():
        gg = genesis_mod.build_genesis(net)
        assert genesis_mod.validate_genesis(gg, net), f"{name} genesis"
        assert gg.header.meets_target(), f"{name} PoW"
        print(f"{name:8s} genesis  {gg.hash.hex()[:32]}…  hrp {net.hrp}  "
              f"p2p {net.p2p_port}  rpc {net.default_rpc_port}")

    exact = reward_mod.exact_total_emission()
    assert exact == 3_149_999_985_930_000, "exact emission"
    assert exact < C.MAX_SUPPLY, "cap respected"
    assert reward_mod.block_reward(reward_mod.last_reward_height()) == 1
    assert reward_mod.block_reward(reward_mod.last_reward_height() +
                                   C.REWARD_INTERVAL) == 0
    print(f"emission         {exact:,} quphi "
          f"({exact / C.QUPHI_PER_QUH:,.4f} QUH), "
          f"{C.MAX_SUPPLY - exact:,} quphi below the cap")
    print(f"                 {reward_mod.epoch_count()} paying epochs, last at "
          f"height {reward_mod.last_reward_height():,}")

    seed, pk, _ = ml_dsa.generate_keypair()
    assert ml_dsa.pk_from_seed(seed) == pk, "keygen determinism"
    msg = b"qeuph build self-check"
    sig = ml_dsa.sign_with_seed(seed, msg)
    assert ml_dsa.verify(pk, msg, sig), "fast backend verify"
    assert ml_dsa.verify_pure(pk, msg, sig), "reference backend verify"
    assert not ml_dsa.verify(pk, msg + b"!", sig), "tamper detection"
    from qeuph.crypto import address as addr_mod
    addr = addr_mod.pk_to_address(pk)
    assert len(addr) == 113 and addr.startswith("quh1"), "address format"
    assert addr_mod.address_to_hash(addr) == addr_mod.pk_to_hash(pk)
    print(f"ML-DSA-87        {ml_dsa.backend_name()} backend; pk {len(pk)} B, "
          f"sig {len(sig)} B; address {addr[:20]}… ({len(addr)} chars)")

    from qeuph.web.server import STATIC_DIRS, STATIC_FILES
    missing = [f for f in STATIC_FILES
               if not any(os.path.isfile(os.path.join(d, f))
                          for d in STATIC_DIRS)]
    if missing:
        raise SystemExit(f"web assets missing: {missing} (looked in "
                         f"{STATIC_DIRS})")
    print(f"web assets       {len(STATIC_FILES)} files in {STATIC_DIRS[0]}")

    print("=" * 62)
    print("build self-check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Build verification script for Qeuph cryptocurrency suite."""
import sys

def main():
    print("Verifying Qeuph core cryptocurrency suite...")
    import qeuph.constants
    import qeuph.config
    import qeuph.crypto.fips204
    import qeuph.crypto.ml_dsa
    import qeuph.crypto.address
    import qeuph.crypto.bech32m
    import qeuph.core.block
    import qeuph.core.chain
    import qeuph.core.difficulty
    import qeuph.core.genesis
    import qeuph.core.mempool
    import qeuph.core.merkle
    import qeuph.core.pow
    import qeuph.core.reward
    import qeuph.core.state
    import qeuph.core.tx
    import qeuph.core.validation
    import qeuph.db.store
    import qeuph.network.protocol
    import qeuph.network.rpc
    import qeuph.node.node
    import qeuph.services.miner
    import qeuph.wallet.wallet
    import qeuph.wallet.keys
    import qeuph.wallet.keystore
    import qeuph.wallet.mnemonic
    import qeuph.cli.main
    import qeuph.main

    # Verify genesis on mainnet
    g = qeuph.core.genesis.build_genesis(qeuph.config.MAINNET)
    assert g.hash == qeuph.core.genesis.MAINNET_GENESIS_HASH
    print(f"Mainnet Genesis verification: OK ({g.hash.hex()[:16]}...)")
    print("Qeuph build completed successfully.")

if __name__ == "__main__":
    main()

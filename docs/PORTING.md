# Porting notes: QRL -> Qeuph

Qeuph is a **hybrid port** of the QRL (Quantum Resistant Ledger) node
codebase (`QRL-master`, Python).  "Hybrid" means the architecture, module
boundaries and node lifecycle were carried over, while the cryptographic
core, consensus and data model were replaced per the Qeuph whitepaper.

## Module mapping

| QRL (src/qrl) | Qeuph (qeuph) | Notes |
|---|---|---|
| `crypto/xmss.py` + `pyqrllib` XMSS trees | `crypto/fips204.py`, `crypto/ml_dsa.py` | XMSS (hash-based, stateful) replaced by ML-DSA-87 (lattice, stateless).  The C-extension dependency is gone: pure Python + optional OpenSSL fast path. |
| `core/Block.py`, `core/BlockHeader.py` (protobuf) | `core/block.py` (canonical binary) | Fixed 168-byte header; protobuf dependency dropped. |
| `core/Transaction.py` + `MessageTypes/` (transfer, coinbase, token...) | `core/tx.py` | QRL's account/balance transfers (with OTS key usage tracking) replaced by UTXO + per-address txnonce. |
| `core/AddressState.py`, `core/State.py` (RocksDB address states) | `core/state.py` (UTXO set + nonce map) | Balance derivation is now UTXO-based; nonce replaces QRL's OTS bitfield. |
| `core/ChainManager.py` | `core/chain.py` | Same responsibilities (connect, validate, fork choice); most-cumulative-work replaces QRL's block signing/stake flow. |
| `core/DifficultyTracker.py` + `pyqryptonight` (Cryptonight PoW) | `core/difficulty.py`, `core/pow.py` | SHA3-512 double-hash PoW with BTC-style 2048-block bounded retarget; no C mining library. |
| `core/formulas.py` (exponential emission decay) | `core/reward.py` | QRL's continuous exponential decay replaced by the whitepaper's geometric "two-thirding" schedule. |
| `core/GenesisBlock.py` (genesis.yml) | `core/genesis.py` | Genesis defined in code with a fixed launch timestamp and mined PoW nonce. |
| `core/TransactionPool.py` | `core/mempool.py` | Fee-ordering template assembly with overlay validation. |
| `core/Miner.py` + `MiningAPIService` | `services/miner.py` | Solo miner thread + RPC control. |
| `core/node.py` (twisted, POW/POS consensus classes) | `node/node.py` (asyncio) | Same sync-state machine (unsynced -> syncing -> synced) with headers-first IBDL. |
| `socket/protocol.py` (protobuf framing over twisted) | `network/protocol.py` | Magic + command + length + dhash-checksum frames carrying JSON payloads. |
| `services/*APIService` (gRPC) | `network/rpc.py` | JSON-RPC 2.0 over HTTP (stdlib). |
| `core/Wallet.py`, `tools/wallet.py` (XMSS JSON wallet) | `wallet/` | Seed-derived ML-DSA keys, AES-256-GCM keystore. |
| `core/config.py` DevConfig + user yaml | `config.py` Network dataclasses | mainnet / testnet / regtest profiles. |
| RocksDB (`plyvel`) persistence | `db/store.py` (SQLite WAL) | Zero native dependencies. |

## What was intentionally kept

* Node lifecycle and sync state machine shape.
* ChainManager / TransactionPool / Miner / Wallet / RPC service separation.
* Bounded difficulty adjustment philosophy (QRL: kp-based controller;
  Qeuph: BTC-style clamped retarget over 2048 blocks).
* Coinbase maturity (QRL: 100 blocks — kept).
* Multi-network dev configuration pattern (QRL dev/testnet/mainnet).

## What was intentionally replaced

* **Signatures**: XMSS 67-neighbor OTS (stateful, one-time keys, huge
  addresses) -> ML-DSA-87 (stateless, 2.5 KB keys, 4.6 KB signatures,
  FIPS 204 Category 5).
* **Consensus**: QRL mainnet is PoW-then-stake; Qeuph is pure PoW with
  SHA3-512 per the whitepaper.
* **Ledger model**: QRL tracks per-address balances and OTS usage;
  Qeuph uses a UTXO set, with the whitepaper's txnonce layered on top.
* **Serialization**: protobuf -> fixed-layout canonical binary (smaller,
  deterministic, no generated code).
* **Services**: gRPC -> JSON-RPC (operationally simpler, curl-friendly).

## FIPS 204 implementation notes

`qeuph/crypto/fips204.py` implements the final standard (August 2024):

* KeyGen_internal with domain separation `H(xi || k || l, 128)`
* Sign_internal (hedged + deterministic), Verify_internal
* ExpandA (SHAKE128), ExpandS, ExpandMask, SampleInBall, RejNTTPoly
* NTT with the Appendix B zeta table (zeta^BitRev8(k), zeta = 1753)
* Decompose/UseHint with the (q-1)/32 gamma2 edge-case remap
* Full BitPack/HintBitPack encodings

It is verified against `cryptography` >= 45 (OpenSSL ML-DSA):
seeded keygen equality and mutual signature verification, plus the
zeta-table equality with the standard's appendix.

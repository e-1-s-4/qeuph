# Qeuph (QUH) Post-Quantum Blockchain Mainnet Launch & Network Synchronization

Verification, hardening, and deployment plan to ensure 100% compatibility across the Qeuph CLI node daemon, Web Explorer UI, FIPS 204 ML-DSA-87 cryptography, double SHA3-512 PoW engine, and multi-node P2P mesh for mainnet launch.

### User Review & Critical Decisions

> [!IMPORTANT]
> Key architectural decisions confirmed during Phase 1 clarification:

- **Confirmed Decision 1 (Genesis Configuration)**: Fresh canonical mainnet genesis block is validated against the exact target bits `0x3D0FFFFF` with deterministic winning nonce `355026620` and zero-quphi null-coinbase spend prevention.
- **Confirmed Decision 2 (Web UI & CLI Synchronization)**: Unified Python web service integrating both direct RPC proxying and live node state synchronization, supporting dual-mode (standalone CLI daemon with headless RPC, or embedded explorer service).
- **Confirmed Decision 3 (Network Topology & Bootstrapping)**: Multi-node cluster with DNS seed fallbacks and dedicated peer discovery, allowing local cluster orchestration transitioning smoothly to public Internet seed nodes.

---

### 1. Overview & Core Concept

- **What It Does**: Qeuph is a post-quantum proof-of-work Layer-1 cryptocurrency implementing FIPS 204 ML-DSA-87 lattice-based digital signatures, double SHA3-512 proof-of-work, Bech32m addresses (`quh1...`), a UTXO + transaction nonce ledger, and a two-thirding emission curve capped at 31,500,000 QUH.
- **Target Audience / Persona**: Miners, node operators, developers, and crypto holders requiring quantum-immune transaction security without relying on ECDSA or Ed25519.
- **Key Value**: Guarantees immunity against Shor's algorithm on quantum computers while providing a zero-dependency pure-Python consensus engine with an interactive Web Explorer UI and scriptable CLI.

---

### 2. User Experience & Visual Design

- **Key User Flows**:
  1. *Node Dashboard*: Real-time monitoring of block height, difficulty, epoch reward, peer mesh count, and solo miner hashrate.
  2. *Quantum Wallet*: Seed phrase generation (BIP-39 style with ML-DSA-87 master key derivation), encrypted keystore persistence (`.qeuph/wallets/`), Bech32m address management, and quantum-signed transaction dispatch.
  3. *Block & Mempool Explorer*: Canonical block inspection, Merkle root verification, transaction input/output scripts, and pending mempool transactions.
  4. *Mainnet Launch Runbook*: Integrated command-line orchestration tools for genesis validation, seed nodes bootstrapping, and remote RPC access.
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Dark slate developer & cryptographic telemetry console adhering strictly to high-density SaaS dashboard standards.
  - *Color Palette & Mood*: Deep dark canvas (`#060911`), structural containers (`#0f172a`), hairline borders (`#1e293b`), sharp cyan accents (`#06b6d4`), and semantic status indicators (green for synched peers, amber for retargeting, red for validation failures).
  - *Typography & Hierarchy*: Display titles in `Plus Jakarta Sans`, data grids and telemetry metrics in monospace tabular numerals (`JetBrains Mono`, `tabular-nums`).
- **Interactive Feedback & Motion**:
  - Instantaneous feedback under 150ms for RPC queries and block checks.
  - Live polling with backoff for mempool and peer count updates.
  - Zero pill enclosures for static metadata; clean unboxed typography with dot separators.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: Zero Third-Party Mandatory Runtime Dependencies**
  - *Chosen Approach*: Maintain pure Python standard library (`hashlib`, `socket`, `sqlite3`, `http.server`, `urllib`) for all core node, consensus, wallet, and web services.
  - *Why*: Eliminates supply-chain vulnerabilities and ensures the entire blockchain runs out-of-the-box on any standard Python 3.10+ runtime without complex C compilation requirements.
  - *Trade-Off*: ML-DSA-87 signature verification in pure Python takes ~15–20ms per transaction, which is accelerated dynamically if optional `cryptography` is present.
- **Decision 2: Dual Mode Web Explorer & CLI Daemon**
  - *Chosen Approach*: Support both direct embedded node mode (`python3 -m qeuph.web.server`) and detached remote node mode (`--remote-rpc http://127.0.0.1:19091`).
  - *Why*: Allows solo users to click-and-run a single process while allowing mainnet validators to run hardened headless nodes isolated from the web interface.

---

### 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Qeuph L1 Blockchain Node                        │
└────────────────────────────────────────────────────────────────────────┘
          ▲                                                     ▲
          │ P2P Protocol (TCP 19090)                            │ JSON-RPC (HTTP 19091)
          ▼                                                     ▼
┌───────────────────┐    ┌────────────────────┐    ┌─────────────────────┐
│  P2P Mesh Network │    │ Consensus Engine   │    │  Web UI & Explorer  │
│  - Peer handshake │◄──►│  - FIPS 204 ML-DSA │◄──►│  - Live node sync   │
│  - Inv/GetData    │    │  - 2x SHA3-512 PoW │    │  - Quantum Wallet   │
│  - Block & TX sync│    │  - UTXO Database   │    │  - RPC Playground   │
└───────────────────┘    └────────────────────┘    └─────────────────────┘
          ▲                         ▲                         ▲
          │                         │                         │
┌───────────────────┐    ┌────────────────────┐    ┌─────────────────────┐
│   CLI Interface   │    │  Storage Engine    │    │ Solo & Pool Mining  │
│  - qeuph node     │    │  - SQLite (WAL)    │    │  - 16-byte nonce    │
│  - qeuph wallet   │    │  - Block headers   │    │  - Multi-threaded   │
│  - qeuph chain    │    │  - UTXO index      │    │  - Coinbase payout  │
└───────────────────┘    └────────────────────┘    └─────────────────────┘
```

- **Data Models**:
  - `BlockHeader`: 168 bytes canonical binary format (version, prev_hash 64B, merkle_root 64B, timestamp 8B, bits 4B, height 8B, nonce 16B).
  - `Transaction`: Vector of `TxIn` (prev_txid 64B, out_idx 4B, sequence 4B, signature up to 4627B, pubkey 2592B) and `TxOut` (value 8B, script_hash 64B).
  - `StateDB`: SQLite with WAL journal mode storing UTXOs (`outpoint -> (value, script_hash, height, is_coinbase)`), block index, and undo data for reorgs up to 2048 blocks.
- **Verification Strategy**:
  - Complete conformance verification against whitepaper consensus parameters (`tools/wp_conformance.py`).
  - End-to-end multi-node mesh sync test (`tools/e2e_three_nodes.py`).
  - Web explorer HTTP & JSON-RPC integration test (`tools/web_smoke.py`).
  - Network profile boundary test (`tools/network_check.py`).

---

### 5. Step-by-Step Mainnet Launch Guide

This runbook guides operators through launching the Qeuph mainnet from genesis:

1. **Environment Preparation**:
   ```bash
   python3 -m qeuph.cli.main preflight --network mainnet
   ```
   Validates system requirements, data directory permissions, and port availability (P2P `19090`, RPC `19091`).

2. **Genesis Block Verification**:
   ```bash
   python3 tools/wp_conformance.py
   python3 -m qeuph.cli.main genesis --network mainnet
   ```
   Confirms the deterministic mainnet genesis block hash (`0000000d2f105b23...`), timestamp (`2026-10-01 00:00:00 UTC`), and Merkle root.

3. **Deploying the First Bootstrap Seed Node (Node A)**:
   ```bash
   python3 -m qeuph.cli.main node --network mainnet --datadir ~/.qeuph/mainnet-seed1 --listen 0.0.0.0:19090 --rpc 127.0.0.1:19091
   ```

4. **Connecting Additional Peer Nodes (Node B, Node C)**:
   ```bash
   python3 -m qeuph.cli.main node --network mainnet --datadir ~/.qeuph/mainnet-node2 --connect <NODE_A_IP>:19090
   ```

5. **Launching the Web Explorer & UI Node**:
   ```bash
   python3 -m qeuph.web.server --network mainnet --port 3000 --connect <NODE_A_IP>:19090
   ```
   Or attach to an existing local node:
   ```bash
   python3 -m qeuph.web.server --network mainnet --port 3000 --embedded-node off --remote-rpc http://127.0.0.1:19091
   ```

6. **Wallet Setup & Solo Mining**:
   ```bash
   # Generate quantum wallet
   python3 -m qeuph.cli.main wallet create --network mainnet

   # Start solo miner to secure mainnet tip
   python3 -m qeuph.cli.main mine --network mainnet --threads 4 --payout <YOUR_QUH_ADDRESS>
   ```

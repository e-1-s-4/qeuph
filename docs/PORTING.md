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

## Deviations from the original port, and why

The first pass of this codebase carried a few QRL-isms that turned out to be
liability rather than heritage. The changes below are the ones worth knowing
about when comparing this tree to `QRL-master`.

| area | first pass | now | reason |
|---|---|---|---|
| `ChainState` identity | a reorg swapped the object, but the mempool had cached it | everything reaches state through `chain.state` / `chain.state_provider()`; the mempool detects the identity change and re-validates | a stale UTXO set after a reorg means the node validates against a chain that no longer exists |
| Store writes | block row, index entry and UTXO delta committed separately | one transaction per block, tip pointer last, `synchronous=FULL` | a crash between commits left the store describing a block the state did not contain |
| Canonical index | trusted on load | re-verified on load; a damaged index replays to the last provable block | the incremental UTXO tables are only meaningful against an intact index |
| Network profiles | a mutable dataclass; the web UI mutated a module-level singleton | frozen dataclass, `Network.with_()` for overrides | a global mutated out from under another component |
| `Network` check in wallet | none | the keystore records the network and a mismatch is refused | a mainnet wallet opened as testnet silently reports zero balances |
| Headers-first IBD | `BlockHeader.hash` was a method but called as a property | fixed; the two-node sync test now covers the real path | the handler raised on every `headers` message, so initial sync never started |
| `mature` in RPC/UI | computed from `confirmations`, one off consensus | shared `is_mature()` helper used by validation, RPC, UI and CLI | a wallet could be told an output was spendable when the node would reject the spend |
| Mempool | rebuilt its overlay per insert | ancestor-depth limit, exact fee caching, reorg resync | unbounded chained pending spends and O(n) rebuilds |
| Peers | no scoring, no ban table, unbounded block requests | token bucket, persistent 24 h ban table, batched requests, `notfound` | eclipse and memory-exhaustion vectors |
| Passphrase | prompted unconditionally | `--passphrase`, `$QEUPH_WALLET_PASSPHRASE`, then a prompt only on a TTY | a piped or containerised run hung forever |
| `exact_total_emission` | carried a dead `if False else` branch | `epoch_rewards()` iterates the floor once and every view derives from it | the old shape hid the rule the total depends on |
| `last_reward_height` | returned the start of the zero-paying epoch | returns the start of the final *paying* epoch (11,130,000) | matches the whitepaper's wording |
| BIP-39 wordlist | 2047 words, `"tragic"` missing | complete 2048-word list, verified against the `mnemonic` reference | a wallet could raise `IndexError` on 1 seed in 2048, and every phrase past index 1846 was misaligned |
| Web UI | returned the master seed and the recovery phrase over HTTP | refused and redacted | an unauthenticated HTTP response is not a place for a seed |
| RPC | no auth, no batches, HTTP 4xx for application errors | Basic auth, batch arrays, JSON-RPC error objects with HTTP 200 | matches JSON-RPC 2.0 and makes the port safe to expose deliberately |
| pytest | a root-level `pytest.py` shim shadowed the real runner | removed; `pyproject.toml` holds the config | `python -m pytest` silently ran a hand-rolled runner instead of pytest |
| packaging | no `pyproject.toml`, so setuptools could not discover packages | a real `pyproject.toml`: explicit package list, package data for the UI assets, `qeuph` console script, `[fast]`/`[dev]` extras | `pip install .` and `pip install -e ".[dev]"` — the two commands the README opens with — both failed outright |
| coin selection | largest-first returned 2+ outputs of the *same* address, all stamped with one nonce | one input per address, with a clear error pointing at `sweep` | the primary spend path could not cover an amount above the largest single UTXO, and the transaction it built was rejected by every node |
| `sweep` nonce | the counter came from the loop position, so a skipped UTXO left a gap | the nonce advances per *emitted* transaction | a gap made every later transaction fail `txnonce == chain_nonce+1` and wedged the address permanently |
| `sweep` fee | a "dust bump" built a 999-quphi transaction, and a dead `change` branch claimed fresh addresses | sub-economic outputs are skipped; the dead branch and its docstring are gone | `sweep --broadcast` reported success for a transaction the relay floor rejects |
| `sign_transaction` | signed every input with one key, overwriting the other public keys | single-input only, with an explicit error | inputs owned by other addresses ended up carrying the sender's key and could never validate |
| wallet index | `_persist()` swallowed every write error | a failed write raises | a full disk silently re-issued an already-used address, defeating the rotation guarantee |
| keystore inputs | KDF iterations and `next_index` were taken from the file unbounded | clamped (`60k..10M`, `0..2^32-1`) | a truncated or hand-edited file made every `Wallet.open` hang, for the web UI too |
| keystore writes | PID-named temp file, no directory fsync, world-readable directory | `mkstemp` + directory fsync, `0700` directory | a predictable temp name could be pre-created as a symlink; a crash could lose the wallet |
| `fips204.sign` | defaulted to `deterministic=True` while its docstring said hedged | hedged by default | any new call site would have silently leaked a repeated signature |
| web: secrets | the response body echoed `argv`, carrying the plaintext passphrase, and the export refusal was matchable around with `--out-mnem` | `argv` is redacted, the parser tree uses `allow_abbrev=False`, and the redaction covers the CLI's own `Master Seed   <hex>` label | the wallet passphrase and the recovery phrase were returned over HTTP |
| web: mainnet | only `/api/miner/start` was guarded | `/api/miner/payout` and the `startminer` RPC are guarded too | arming the miner on mainnet through `/api/rpc` bypassed the UI's own guard |
| web: CORS | `Access-Control-Allow-Origin: *`, no auth | same-origin only | any page the operator visited could drive a wallet that spends funds and stop the node |
| web: command surface | `chain truncate`/`reindex` and `rpc --url` were reachable | per-subcommand allowlist | `chain truncate` destroyed the embedded node's chain, and `rpc --url` was an SSRF primitive |
| web: availability | unbounded `?count=`, no socket timeout, two responses per request on some error paths | clamped, `timeout = 120`, `HttpError` | one GET could permanently wedge the server, and an error path desynchronised keep-alive |
| rpc: transport | a promised rate limit that was never wired up; mutating methods over GET; a non-ASCII `Authorization` crashed the handler | token bucket, read-only GET allowlist, bytes-safe auth compare | an unauthenticated flood or a plain `<img>` tag could drive the node |
| rpc: blocking | `generate` mined inline on the event loop; `rescan` held `chain.lock` for a full re-validation | PoW in a worker thread; `rescan` outside the lock | one RPC call could stop the node servicing P2P and mempool traffic |
| lock ordering | `_block_template` and the mempool took `chain.lock` and `mempool.lock` in opposite orders | mempool resolves height/MTP before locking; callers select before locking | a hard deadlock between an RPC thread and the event loop |
| amounts | `round(x * 10**8)` on a binary float | `Decimal` with an exact-integer check | typed amounts did not always mean what was written, and banker's rounding could cost a quphi |

## Testing approach

The suite is written against the *protocol*, not the implementation, so a
behaviour change that contradicts the whitepaper shows up as a failure in
`test_whitepaper.py` rather than as a silently different chain. Two-node sync,
the RPC surface and the web surface are exercised against real listeners and
real sockets rather than mocks, because every bug found during this pass lived
in the wiring rather than in the units.

### Handshake traps found while hardening

Three faults in the original handshake only appeared once two real daemons
talked to each other, and all three are now covered by tests in
`tests/test_p2p_sync.py`:

1. **Stale advertised height.** A peer's view of our height is a snapshot
   from its `version` message.  Two nodes that were level at handshake time
   and then diverged (one mined) never noticed: the sync driver compares the
   local tip against `peer.best_height`, so a stale value read as "synced"
   forever.  The fix re-advertises on `verack`, after every connected block,
   and on a periodic interval — coalesced so a fast sync does not turn into
   one frame per block, with the suppressed tail flushed once the burst
   settles (otherwise a dozen blocks mined inside one throttle window left
   the peer convinced it was level).
2. **`verack` answered more than once.** Making the height refresh a
   `version` message meant the peer's `_on_version` replied `verack` again,
   whose `_on_verack` replied `version` again: a tight ping-pong that the
   token-bucket rate limiter resolved by disconnecting both peers.  `verack`
   is now sent exactly once per connection.
3. **A `--connect` peer that is not listening yet.** The daemon only dialed
   the configured peers once, in `start()`.  Start the peer a moment later and
   the node sat idle until the next 15-second discovery sweep.  Configured
   peers are now retried on a 1s→10s backoff.  Separately, the discovery
   sweep pre-claimed the in-flight dial slot, which made `_connect_peer` see
   its own key in that set and skip the dial entirely.

`_connect_peer` establishes a connection and then *serves* it for the
connection's whole lifetime, so it only returns when the peer disconnects. It
must always be scheduled as a task, never awaited from the caller's flow.

# Qeuph (QUH)

A complete, quantum-resistant cryptocurrency node suite. Qeuph is a hybrid
port of the [QRL](https://github.com/theQRL/QRL) (Quantum Resistant Ledger)
architecture — the first serious post-quantum ledger — rebuilt around
**ML-DSA-87** lattice signatures, **double SHA3-512** hashing and
**Bech32m** addresses, with a two-thirding reward schedule that converges on a
hard 31,500,000 QUH cap.

**Whitepaper:** [`Qeuph_QUH_Whitepaper.pdf`](Qeuph_QUH_Whitepaper.pdf) ·
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) pins the byte formats and consensus
rules · [`docs/PORTING.md`](docs/PORTING.md) maps QRL → Qeuph.

| Property | Value |
|---|---|
| Signatures | **ML-DSA-87** (FIPS 204, NIST category 5) |
| Hashing | **double SHA3-512** (tx ids, block ids, addresses, PoW) |
| Addresses | **Bech32m** (BIP-350), HRP `quh`, 512-bit payload, 113 chars |
| Consensus | **pure proof of work** (double SHA3-512), 5 minute blocks |
| Difficulty | retarget every **2048 blocks** (~7.1 days), bounded ±4x |
| Reward | **50 QUH × (2/3)^epoch**, floored, every 210,000 blocks |
| Supply | 31,500,000 QUH cap — exact emission **31,499,999.8593 QUH** |
| Divisibility | 8 decimals — 1 QUH = 100,000,000 **quphi** |
| Transactions | **UTXO + txnonce** hybrid, one input per address per tx |
| Coinbase maturity | 100 blocks |
| Block size | 2 MB |
| Ports | P2P 19090, JSON-RPC 19091, web UI 3000 (mainnet) |

Everything is pure Python 3.10+ with **no mandatory dependencies**. Install
`cryptography>=45` for the OpenSSL/AWS-LC ML-DSA-87 backend (~50,000
signatures/s instead of ~20/s in the reference implementation).

---

## Install

```bash
git clone <this repo> && cd qeuph
pip install .            # or: pip install -e ".[dev]" for the test extras
```

This puts a `qeuph` command on your `PATH`. Without installing, every example
below also works as `python3 -m qeuph.cli.main <args>`.

```bash
python3 -m qeuph.cli.main version     # check the build
python3 -m qeuph.cli.main genesis     # verify the pinned mainnet genesis
```

---

## Quick start

### Run a node

```bash
# mainnet
python3 -m qeuph.cli.main node --network mainnet

# a second node on the same host (port overrides)
python3 -m qeuph.cli.main node --network regtest --p2p-port 39190 --rpc-port 39191 \
    --connect 127.0.0.1:39090

# solo mine to your address
python3 -m qeuph.cli.main node --network mainnet --mine quh1... --threads 4

# protect the RPC port (it is full node control: mining, submission, stop)
python3 -m qeuph.cli.main node --rpc-user operator --rpc-password "$RPC_PASS"
```

Use `--network regtest` (instant mining) or `--network testnet` for iteration.

### Use a wallet

```bash
# create (prints the 24-word recovery phrase — back it up immediately)
python3 -m qeuph.cli.main wallet create --network mainnet

# addresses + balances (the seed stays hidden)
python3 -m qeuph.cli.main wallet show --count 5 --rpc http://127.0.0.1:19091/

# derive the next unused (persisted) receiving address
python3 -m qeuph.cli.main wallet newaddress --network mainnet

# send (change automatically goes to a fresh address)
python3 -m qeuph.cli.main wallet send --to quh1... --amount 1.5 \
    --fee 0.01 --rpc http://127.0.0.1:19091/

# back up / restore
python3 -m qeuph.cli.main wallet backup --out ~/quh-backup.json --new-passphrase "$PW"
python3 -m qeuph.cli.main wallet restore --from-mnemonic "word word ..."
python3 -m qeuph.cli.main wallet mnemonic          # ONLY on a trusted terminal
```

In a non-interactive context (containers, CI, the web UI) pass
`--passphrase` or set `QEUPH_WALLET_PASSPHRASE`; the CLI never hangs waiting
for a prompt it cannot show.

### Inspect the chain

```bash
python3 -m qeuph.cli.main chain info                  # offline, no node needed
python3 -m qeuph.cli.main chain blocks --limit 20
python3 -m qeuph.cli.main chain block 12345
python3 -m qeuph.cli.main chain verify                # re-validate every block
python3 -m qeuph.cli.main emission                    # the two-thirding schedule
```

---

## The web UI

The node explorer, quantum wallet and miner console are served by a
Python module. The `package.json` exists purely to give it a familiar
one-word launcher — **there is no JavaScript build step and no npm
dependency**.

```bash
python3 -m qeuph.web.server      #  -> http://127.0.0.1:3000/
```

```bash
npm run start                    # identical: runs the same module
```

```bash
qeuph web --port 8080            # identical, after `pip install .`
```

All three start the same server. Options:

| flag | meaning |
|---|---|
| `--host` | bind address (default `127.0.0.1`) |
| `--port` | HTTP port (default `3000`) |
| `--network` | `regtest` \| `testnet` \| `mainnet` for the embedded node |
| `--embedded-node` | force a network, or `off` for a read-only view of an external node |
| `--data-root` | where the embedded node keeps `chain.db` |
| `--port-offset` | shift the embedded P2P/RPC ports so a second instance can run |
| `--allow-remote` | permit a non-loopback bind (you own the firewall) |

`npm run` shortcuts: `start`, `dev` (verbose), `regtest`, `testnet`,
`mainnet` (read-only), `node`, `node:mainnet`, `cli`, `test`, `smoke:web`.

### How the UI stays in sync with the CLI

The browser never talks to a private back door:

* **Reads** go through `/api/*` views built from the same objects the daemon
  uses (chain, mempool, node, miner).
* **Writes** go through `POST /api/rpc`, which is the *same*
  `RPCService.dispatch` the JSON-RPC daemon exposes on port 19091.
* **Commands** go through `POST /api/cli` and `POST /api/wallet`, which run
  the literal `qeuph` subcommands in-process. `GET /api/cli` returns the live
  argparse tree, so the in-browser console can never offer an option the CLI
  does not have. Run `node`, `web` and `wallet` key material commands are
  refused from the browser.

### Key safety properties of the UI

* The **node never holds keys.** A wallet stays sealed on disk
  (AES-256-GCM under PBKDF2-HMAC-SHA3-512) and is unlocked per request with a
  passphrase that is never stored.
* The **master seed and the 24-word recovery phrase are never returned over
  HTTP.** `wallet mnemonic` and `wallet backup --out-mnemonic` are refused by
  the web route, and any phrase-shaped or seed-shaped text in CLI output is
  redacted before it leaves the process. Use `qeuph wallet mnemonic` in a
  terminal you trust.
* The server **binds loopback by default** and refuses any other address
  without `--allow-remote`.
* It runs **regtest by default**, and the miner controls are disabled on
  mainnet, so the UI cannot spend or reorganise real value by accident.
* Network switching derives a new immutable profile; the module-level
  mainnet/testnet/regtest configuration can never be mutated.

---

## JSON-RPC

The node exposes JSON-RPC 2.0 at `http://127.0.0.1:19091/`:

```bash
curl -s localhost:19091 -d '{"jsonrpc":"2.0","id":1,
  "method":"getblockchaininfo","params":{}}' | python3 -m json.tool

# or through the CLI
python3 -m qeuph.cli.main rpc getblockchaininfo
python3 -m qeuph.cli.main rpc getblock --url http://127.0.0.1:19091/ '{"height": 0}'
```

* `POST` with a JSON-RPC 2.0 document, or a **batch** (a JSON array).
* `GET /?method=…&params=…` for read-only calls.
* Application errors come back as JSON-RPC `error` objects with HTTP 200, as
  the specification requires; only transport faults use 4xx.
* Optional HTTP Basic auth via `--rpc-user` / `--rpc-password`.

Methods (see `rpc help`):

| group | methods |
|---|---|
| chain | `getblockchaininfo` `getblockcount` `getbestblockhash` `getdifficulty` `getblockhash` `getblock` `getblockstats` `gettxout` `getchaintips` `getrewardinfo` |
| transactions | `gettransaction` `getrawtransaction` `sendrawtransaction` `decoderawtransaction` `createrawtransaction` `signrawtransaction` |
| mining | `getblocktemplate` `submitblock` `getmininginfo` `startminer` `stopminer` `generate` |
| mempool | `getmempoolinfo` `getrawmempool` `getmempool` |
| wallet / address | `getbalance` `listutxos` `listunspent` `getnonce` `validateaddress` `getaddressinfo` |
| network | `getnetworkinfo` `getpeerinfo` `getconnectioncount` `getnettotals` `getnodeinfo` `uptime` `stop` |
| admin | `help` `savewallet` `rescan` |

`signrawtransaction` and `savewallet` deliberately return an error: signing
and key storage belong in the wallet process, not the node, so private keys
never have to reach an RPC surface.

---

## Cryptography

* **Signatures** — ML-DSA-87 per FIPS 204 (final).
  `qeuph/crypto/fips204.py` is a dependency-free reference implementation of
  Algorithms 5–48, cross-verified against OpenSSL/AWS-LC (`cryptography` ≥ 45):
  seeded keygen produces byte-identical public keys and each backend verifies
  the other's signatures. The fast backend is used automatically when
  available.
* **Addresses** — `bech32m("quh", SHA3-512(SHA3-512(pk)))`. The full 64-byte
  digest is the payload, so a collision is a 512-bit preimage problem even for
  a quantum adversary. Qeuph deliberately exceeds BIP-350's 90-character limit
  (113 characters); BIP-350's error detection holds to 1023 characters.
* **PoW** — block hash = double SHA3-512 over the 168-byte header; valid when
  the hash as a big-endian integer is below the compact `bits` target.
* **Signing is hedged by default** (FIPS 204's randomised variant), so
  repeated signatures of the same message do not leak anything. Use
  `deterministic_sign` when reproducibility is required.

```bash
python3 -m qeuph.cli.main crypto info     # parameters + which backend is live
python3 -m qeuph.cli.main crypto test     # live sign / verify / tamper test
python3 -m qeuph.cli.main crypto bench    # keygen / sign / verify rates
```

---

## Transaction model (UTXO + txnonce)

Transactions spend unspent transaction outputs. Every input additionally
carries a **txnonce**: the per-address strictly-increasing counter of the
whitepaper. A transaction is valid when

```
input.txnonce == chain_nonce(address) + 1
```

which gives deterministic ordering and replay protection on top of the UTXO
model, independently of which UTXO is spent. Because the rule is per *address*,
a single transaction may spend at most one output of any given address — the
wallet's `sweep` therefore chains one transaction per output with nonces
`n, n+1, …`.

Each input carries an ML-DSA-87 signature over
`dhash(sigless-tx) || LE32(input_index)`, so every byte of the transaction —
including the other inputs' public keys, all outputs, the lock time and every
other input's nonce — is committed by every signature.

Outputs below the dust threshold (1,000 quphi) are rejected, for both relay
and block inclusion, so the UTXO set cannot be filled with uneconomic entries.

---

## Two-thirding reward schedule

```
reward(h) = floor(50 QUH × (2/3)^floor(h / 210000))
```

The floor is applied **per epoch**, exactly as Bitcoin floors its halvings —
iterating, not exponentiating. That is what makes the total exact:

| epoch | height | reward | cumulative |
|---|---|---|---|
| 0 | 0 | 50.00000000 QUH | 10,500,000.000 |
| 1 | 210,000 | 33.33333333 | 17,499,999.999 |
| 2 | 420,000 | 22.22222222 | 22,166,666.666 |
| 3 | 630,000 | 14.81481481 | 25,277,777.776 |
| … | … | … | … |
| 53 | 11,130,000 | 0.00000001 (1 quphi) | 31,499,999.859 |
| 54+ | 11,340,000 | 0 (fees only) | 31,499,999.859 |

The geometric series sums to at most 3 × 50 QUH × 210,000 = 31,500,000 QUH;
the iterated floor lands at 31,499,999.8593 QUH, i.e. **0.1407 QUH below the
cap** — Qeuph's analogue of Bitcoin never quite reaching 21M. At 5-minute
blocks the schedule runs ~108 years.

> Note: Table 5 of the whitepaper lists 0.86616069 for epoch 10 and
> 0.00014994 for epoch 20. The iterated floor this implementation applies
> yields 0.86707648 and 0.01503642, and *those* are the values that
> reproduce the paper's own stated total of 31,499,999.8593 QUH and its
> "0.1407 QUH below the cap" claim. See `docs/PROTOCOL.md`.

---

## Genesis

Mainnet genesis (timestamp 2026-10-01 00:00:00 UTC, bits `0x3D0FFFFF`,
nonce 355026620):

```
0000000d2f105b239cd085e9d4bd7fa087dc6a085ee37b3842d539ab9c974247
fa8c4000695807b0a5d306d40c713e32b130387f72b64a00bf2b0c9953b179b1
```

`qeuph genesis` rebuilds it from the pinned constants and verifies the hash,
the message, the PoW and the checkpoint match. No node ever mines genesis at
startup.

---

## Repository layout

```
qeuph/
├── qeuph/
│   ├── constants.py config.py      network parameters + immutable profiles
│   ├── crypto/                     fips204.py, ml_dsa.py, bech32m.py, address.py
│   ├── core/                       tx, block, chain, state, mempool,
│   │                               validation, difficulty, pow, reward, genesis
│   ├── db/store.py                 SQLite persistence (WAL, atomic transitions)
│   ├── network/                    p2p protocol + JSON-RPC
│   ├── node/node.py                asyncio full node service
│   ├── services/miner.py           solo miner
│   ├── wallet/                     keys, keystore (AES-256-GCM), mnemonic, wallet
│   ├── main.py                     daemon wiring
│   ├── cli/main.py                 command line interface
│   └── web/server.py               node explorer + CLI-synced HTTP surface
├── web/                            index.html, app.js, style.css, favicon.svg
├── tests/                          365 tests
├── tools/                          mine_genesis.py, web_smoke.py
└── docs/                           PORTING.md, PROTOCOL.md
```

---

## Testing

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -q
```

365 tests, no network access required, ~100 s. Coverage:

* **Whitepaper conformance** (`test_whitepaper.py`) — the pinned genesis
  hash, every Appendix A parameter, the Table 5 emission values, the
  difficulty clamps, the 113-character address format and BIP-350's error
  detection.
* **FIPS 204** (`test_fips204.py`) — NTT round trips, pack/unpack
  round trips, hint encoding, malformed-signature rejection, seeded keygen
  determinism, cross-verification against OpenSSL/AWS-LC in both directions.
* **Consensus** (`test_tx.py`, `test_chain.py`, `test_overhaul.py`) —
  signature coverage, txnonce ordering and replay, maturity, lock time,
  dust, duplicate inputs/outputs, duplicate transaction ids in a block,
  coinbase rules, merkle tampering, invalid PoW, wrong difficulty.
* **Reorganisation** — most-cumulative-work fork choice at depth, state and
  address-index restoration, invalid side chains discarded, mempool revival,
  and the state-object-identity rule that keeps a pool correct across a reorg.
* **Persistence** (`test_persistence.py`) — incremental deltas equal a full
  replay, block-atomic writes, a damaged canonical index self-heals by
  truncating to the last provable block, reindex/verify/truncate.
* **P2P** (`test_p2p.py`, `test_p2p_sync.py`) — framing and checksums, magic
  isolation per network, a real two-node headers-first sync with UTXO
  transfer, block and transaction relay, `getaddr`/`addr` exchange, prompt
  shutdown with a silent peer, and the peer rules (network mismatch, protocol
  version, clock skew, rate limit, address flood). It also covers the three
  handshake traps found while hardening this: `verack` must be answered only
  once (answering a height refresh starts a version/verack ping-pong that the
  rate limiter then turns into a mutual disconnect), a peer's view of our
  height must be re-advertised or a node that was level at handshake time
  never notices it fell behind, and a `--connect` peer that is not listening
  yet must be retried instead of waiting for the next discovery sweep.
* **RPC** (`test_rpc.py`) — JSON-RPC 2.0 conformance, batch handling, Basic
  auth, and the full method set against a live node.
* **Wallet** (`test_wallet_suite.py`) — derivation, the official BIP-39
  vectors, keystore permissions and re-encryption, network-mismatch refusal,
  coin selection, dust handling, fresh change addresses, sweeping.
* **CLI** (`test_cli.py`) — every subcommand, plus the assertion that the web
  console's option list is read from the same parser.
* **Web** (`test_web.py`) — every HTTP route, the CLI mirror, and the safety
  properties (no key material in any response, mnemonic refused, loopback
  enforced, mining disabled on mainnet).
* **Integration** (`test_integration.py`) — boots the real daemon, mines past
  maturity, settles transfers and exercises the RPC surface.

Two developer checks drive real daemons over real sockets:

```bash
python3 tools/web_smoke.py    # web suite: HTTP routes, CLI mirror, mine+send
python3 tools/e2e_check.py    # two regtest daemons, P2P sync, send, reindex, auth
```

---

## Mainnet readiness checklist

* **Chain identity** — genesis hash pinned and re-verified on every start; a
  mismatch in the build is a loud startup failure, not a silent fork.
* **Crash safety** — every block connection is one SQLite transaction
  (`synchronous=FULL`, WAL) that advances the tip pointer last. A crash leaves
  the store on a block boundary; the canonical index is re-verified on load and
  a damaged index self-heals by replaying to the last provable block.
* **Fork choice** — every stored block carries cumulative work; any competing
  chain is validated block-by-block against a scratch state *before* anything
  is committed, and an invalid side chain is discarded. Orphan blocks are
  bounded and expire.
* **Peer hygiene** — per-network magic, protocol/network version checks,
  per-peer token-bucket rate limits, a bounded per-connection frame buffer, a
  misbehaviour score with a persistent 24-hour ban table, `notfound`
  responses, and batched block requests so a peer cannot make the node request
  thousands of 2 MB blocks at once.
* **Mempool** — admission-time fee caching, per-address nonce chaining, an
  ancestor-depth limit, byte-budget eviction, expiry sweeping, and a reorg
  resync.
* **RPC** — loopback by default, optional Basic auth, batch support, spec
  error semantics, and no signing or key storage on the node.
* **Wallet** — AES-256-GCM with 600,000 PBKDF2-HMAC-SHA3-512 iterations
  (configurable), 0600 permissions, atomic writes, network binding, and a
  persisted next-address index so restarts never re-issue an address.
* **Shutdown** — SIGINT/SIGTERM and the RPC `stop` method all resolve to the
  same event; peer writers close before the server waits, so shutdown is
  prompt even with silent peers connected.
* **Before you launch** — mainnet ships with the genesis block, the chain
  parameters, the pinned genesis checkpoint, and the consensus code. Three
  things are intentionally *not* in the repository, because they are yours to
  publish: real bootstrap node addresses, DNS seed hostnames, and periodic
  block checkpoints. A node with none of them starts, validates and serves
  RPC perfectly well, but cannot find the network on its own — `preflight`
  says so explicitly on every start.

  ```python
  # qeuph/constants.py
  BOOTSTRAP_NODES_MAINNET = [("node1.example.org", 19090), ...]
  DNS_SEEDS_MAINNET = ["seed1.example.org", ...]
  CHECKPOINTS = {0: GENESIS_HASH, 210000: b'\x..', ...}
  ```

  For a private network or a single-machine test, skip all of it and pass
  `--connect host:port` (repeatable) or `--seed host` instead. Those override
  the constants, so nothing needs to be edited.

---

## Security notes

* ML-DSA-87 is FIPS 204 conformant; hedged signing is the default.
* Wallets are sealed with AES-256-GCM + PBKDF2-HMAC-SHA3-512. A documented
  SHA3-512 keystream fallback with encrypt-then-MAC exists for
  cryptography-free environments and is clearly flagged in the file.
* The pure-Python FIPS 204 implementation is not constant-time; hardened
  deployments should rely on the OpenSSL backend (the same guidance FIPS 204
  gives for deterministic signing).
* Post-quantum signatures are large (4,627 B each): a 1-in-2-out Qeuph
  transaction is ~7.5 KB, so a 2 MB block holds roughly 250 of them.
* The reference miner sustains about 0.3 MH/s per core — double SHA3-512
  dominates. Use it for regtest, for template checks and for benchmarking;
  real mainnet hashrate needs a native SHA3-512 kernel.
* `lock_time` is enforced (Bitcoin semantics: height-locked below
  500,000,000, median-time-past-locked at or above it).
* Change outputs default to fresh derived addresses (whitepaper 6.1).

---

## License

MIT — acknowledging the QRL project whose node architecture this codebase
ports. See [LICENSE](LICENSE).

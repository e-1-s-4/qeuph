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

### Check a build before you launch it

```bash
python3 -m qeuph.cli.main preflight --network mainnet
python3 -m qeuph.cli.main preflight --network testnet --json
```

`preflight` starts nothing, mines nothing and touches no wallet: it rebuilds
the genesis block and compares it with the pinned mainnet checkpoint, runs a
live ML-DSA-87 sign/verify/tamper self-test, re-derives the total emission
against the 31.5M cap, probes the data directory and both ports, looks for a
foreign `chain.db`, and reports whether any peers or DNS seeds are configured
(or whether only the genesis checkpoint is pinned, or mainnet has not launched
yet). Every check prints as `ok` / `warn` / `fail`; the exit code is non-zero
if anything failed.

The same checks run at daemon start-up and are logged as warnings, so what
`preflight` prints is exactly what `qeuph node` will say on this machine.
It is also reachable from the web console (`POST /api/cli` with
`preflight`), because it reads only local state.

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
| `--embedded-node` | force a network, or `off` to ATTACH the UI to `--remote-rpc` |
| `--remote-rpc URL` | with `--embedded-node off`: the external node's JSON-RPC endpoint |
| `--connect HOST:PORT` | P2P peer the embedded node dials (repeatable) — joins the mesh formed by `qeuph node` daemons |
| `--p2p-host` | interface the embedded node's P2P listener binds (default `127.0.0.1`; the daemon default is `0.0.0.0`) |
| `--data-root` | where the embedded node keeps `chain.db` |
| `--port-offset` | shift the embedded P2P/RPC ports so a second instance can run |
| `--allow-remote` | permit a non-loopback bind (you own the firewall) |

### The UI node is a full mesh participant

The embedded node RUNS P2P: it dials `--connect` targets, accepts inbound
connections from CLI daemons, syncs headers-first and relays blocks and
transactions like any `qeuph node`. A browser-driven node and a
terminal-driven node are interchangeable:

```bash
# terminal 1: a CLI daemon
python3 -m qeuph.cli.main node --network regtest --p2p-port 39190 --rpc-port 39191

# terminal 2: the UI node, dialing INTO the CLI mesh
qeuph web --network regtest --connect 127.0.0.1:39190

# terminal 3: a second CLI daemon dialing INTO the UI node
python3 -m qeuph.cli.main node --network regtest \
    --p2p-port 39290 --rpc-port 39291 --connect 127.0.0.1:41090
```

Blocks mined anywhere reach all three; a payment made in the browser's Send
form appears in every node's mempool, and one made through
`qeuph wallet send --rpc …` against any node appears in the UI. The full
asserted version of this story (three CLI daemons + the web UI node + a
remote-attach UI instance, both directions, regtest and testnet) is
`python3 tools/e2e_three_nodes.py`.

### Remote-attach mode (thin UI over an external node)

`--embedded-node off --remote-rpc http://127.0.0.1:19091/` turns the suite
into a pure explorer/wallet for an EXISTING daemon: every chain view
(/api/status, /api/blocks, /api/tx/…, /api/address/…) is served from that
node's JSON-RPC, the RPC console forwards to it, miner and generate routes
are refused (the remote node owns its own miner), and wallet operations
still sign LOCALLY — the remote node only ever receives signed
transactions, never keys.

`npm run` shortcuts: `start`, `dev` (verbose), `regtest`, `testnet`,
`mainnet` (read-only), `node`, `node:mainnet`, `cli`, `test`, `smoke:web`.

`qeuph web` takes the same flags as the module (`--network` defaults to
`regtest`, not mainnet) and additionally accepts `--allow-remote`, matching
the loopback policy enforced by the server itself.

### How the UI stays in sync with the CLI

The browser never talks to a private back door:

* **Reads** go through `/api/*` views built from the same objects the daemon
  uses (chain, mempool, node, miner).
* **Writes** go through `POST /api/rpc`, which is the *same*
  `RPCService.dispatch` the JSON-RPC daemon exposes on port 19091.
* **Commands** go through `POST /api/cli` and `POST /api/wallet`, which run
  the literal `qeuph` subcommands in-process. `GET /api/cli` returns the live
  argparse tree, so the in-browser console can never offer an option the CLI
  does not have. `Run`, `node` and `web` key-material commands are refused
  from the browser.

The allowlist is a group *and* a per-subcommand set, so the HTTP surface
cannot reach the dangerous verbs even indirectly:

| route | allowed |
|---|---|
| `POST /api/cli` | `chain info\|blocks\|block\|tx\|verify`, `genesis`, `emission`, `address`, `crypto`, `version`, `preflight` |
| `POST /api/wallet` | `show`, `balance`, `addresses`, `newaddress`, `send`, `sweep`, `verify`, `utxos`, `create` |

`rpc` is excluded because its `--url` is an arbitrary outbound URL (the
browser has `POST /api/rpc` instead), `mine` because it is an unbounded CPU
and thread burner, `chain truncate`/`reindex` because they rewrite or
destroy the embedded node's database, and `wallet sign`/`passwd`/`backup`/
`restore`/`mnemonic` because they touch key material or write to
caller-chosen paths.

### Key safety properties of the UI

* The **node never holds keys.** A wallet stays sealed on disk
  (AES-256-GCM under PBKDF2-HMAC-SHA3-512) and is unlocked per request with a
  passphrase that is never stored.
* The **master seed and the 24-word recovery phrase are never returned over
  HTTP.** `wallet mnemonic` and `wallet backup --out-mnemonic` are refused by
  the web route; the `argv` echoed in the response has `--passphrase` and
  `--from-mnemonic` values masked; phrase-, seed- and secret-key-shaped text
  is redacted from any CLI output before it leaves the process; the wallet
  info view and the create/restore responses never contain a phrase (a
  dashboard GET also never CREATES a wallet — restoring one into the browser
  is the only place a phrase is typed, and it is never echoed back). Use
  `qeuph wallet mnemonic` in a terminal you trust. (The refusal is matched
  against exact option names, and the parser tree is built with
  `allow_abbrev=False`, so `--out-mnem` cannot be used to slip past it.)
* The server **binds loopback by default** and refuses any other address
  without `--allow-remote`. The check uses `ipaddress.is_loopback`, so
  `localhost` and `127.0.0.2` are accepted while `""` and `0.0.0.0` — which
  would bind every interface — are not.
* It runs **regtest by default**, and the miner controls are disabled on
  mainnet, so the UI cannot spend or reorganise real value by accident. The
  guard covers `POST /api/miner/start`, `POST /api/miner/payout` *and* the
  `startminer` RPC method, so arming the miner through `/api/rpc` is not a
  way around it.
* **CORS is same-origin only.** `Access-Control-Allow-Origin: *` is not
  sent; the request's own `Origin` is echoed only when it matches the `Host`.
* Network switching derives a new immutable profile; the module-level
  mainnet/testnet/regtest configuration can never be mutated.
* The HTTP handler carries a 120-second socket timeout, caps request bodies
  at 8 MiB, bounds `?limit=`/`?count=` (an unbounded `count` ran a PBKDF2
  unlock plus a keygen per index and could wedge the server), and emits
  exactly one HTTP response per request.

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

* `POST` with a JSON-RPC 2.0 document, or a **batch** (a JSON array, capped
  at 32 calls).
* `GET /?method=…&params=…` for **read-only** calls. A mutating method over
  GET is refused: a GET is what a link, an `<img>` tag and a cross-origin
  fetch all issue, so the read-only endpoint must not double as a
  node-control surface.
* Application errors come back as JSON-RPC `error` objects with HTTP 200, as
  the specification requires; only transport faults use 4xx.
* Optional HTTP Basic auth via `--rpc-user` / `--rpc-password`.
* 120 calls/second per connection, then HTTP 429; bodies capped at 1 MiB.
* CORS is **same-origin only** — the wildcard `Access-Control-Allow-Origin: *`
  is never sent, because a browser reaches loopback freely and this surface
  can mine, submit blocks and stop the node.
* `startminer` and `generate` are refused on mainnet; the daemon owns the
  solo miner there (`node --network mainnet --mine ADDR`).
* `listutxos`/`listunspent` hide outpoints already spent by a pending
  mempool transaction, and `getnonce` returns `max(chain nonce, pending
  nonce)` — the same overlay picture `add_tx` validates the next
  transaction against, so a wallet can chain payments while the first is
  still unconfirmed.

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

Because the rule is per *address*, a single transaction may spend at most
one output of any given address. That is enforced on both sides: a node
rejects a transaction that presents two inputs from one address, and the
wallet never builds one — `wallet send` funds from a single address and so
spends exactly one of its outputs, refusing an amount above the largest
single output with a message pointing at `sweep` instead of assembling a
transaction every node would reject. `sweep` is the way to consolidate: it
chains one transaction per output with **contiguous** nonces `n, n+1, …`,
paying each output's value minus the fee straight to the destination. An
output too small to cover the relay fee is skipped, and because the counter
advances per *emitted* transaction, skipping one leaves no gap — a gap
would make every later transaction fail `txnonce == chain_nonce + 1` and
wedge the address permanently.

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
│       └── static/                 index.html, style.css, favicon.svg
├── tests/                          427 tests
├── tools/                          mine_genesis.py, web_smoke.py,
│                                   e2e_check.py, e2e_three_nodes.py,
│                                   wp_conformance.py
└── docs/                           PORTING.md, PROTOCOL.md
```

The UI assets live **inside the package** (`qeuph/web/static/`) so the web
suite works identically from a source checkout and from an installed wheel;
they are declared as package data in `pyproject.toml`.

---

## Testing

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -q
```

458 tests, no network access required, ~180 s. Coverage:

* **Launch readiness** (`test_preflight.py`) — the shared report behind
  `qeuph preflight`: genesis/checkpoint identity on all three networks, the
  live ML-DSA-87 self-test, emission against the cap, data-directory and port
  probes, foreign-`chain.db` detection, the peer/checkpoint/launch warnings,
  the CLI's exit codes, and the invariant that the daemon's start-up warnings
  are exactly that report.
* **Listener exclusivity** (`test_port_exclusivity.py`) — the RPC, web and P2P
  listeners cannot be taken over by a second local process on Windows (the
  stdlib's `SO_REUSEADDR` binding can, which is the point), and "port in use"
  is recognised on every platform's errno.
* **P2P admission** (`test_p2p_limits.py`) — the peer ceiling, the per-IP
  inbound cap and the reserved outbound slots are enforced *before* the
  handshake (including against a real connection flood), and a `headers` batch
  is only used when it is rooted in a block we hold, contiguous, and valid
  under its own proof of work.

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
* **RPC** (`test_rpc.py`, `test_rpc_hardening.py`) — JSON-RPC 2.0
  conformance, batch handling, Basic auth, the full method set against a
  live node, the per-connection rate limit, the read-only GET allowlist,
  same-origin CORS, oversized-body handling and exact decimal amount
  conversion.
* **Wallet** (`test_wallet_suite.py`) — derivation, the official BIP-39
  vectors, keystore permissions and re-encryption, network/HRP-mismatch
  refusal, coin selection, dust handling, fresh change addresses, sweeping.
* **Regressions** (`test_regressions.py`, `test_web_regressions.py`) — the
  defects found in the 2026 mainnet-readiness pass, each pinned by a test:
  multi-UTXO sends the node rejects, sweep nonce gaps, sub-fee sweep
  transactions, multi-input signing, unbounded KDF/derivation indices, a
  swallowed index-persist failure, an inverted FIPS 204 signing default, a
  passphrase echoed over HTTP, a mainnet miner reachable through the web
  bridge, and two HTTP/1.1 keep-alive desyncs.
* **CLI** (`test_cli.py`) — every subcommand, plus the assertion that the web
  console's option list is read from the same parser.
* **Web** (`test_web.py`) — every HTTP route, the CLI mirror, and the safety
  properties (no key material in any response, mnemonic refused, loopback
  enforced, mining disabled on mainnet).
* **UI↔CLI sync** (`test_web_sync.py`) — the dashboard Send route end to end
  (sign, mempool, relay, exact decimals), the embedded node joining a real
  `qeuph node` daemon's P2P mesh in BOTH directions, mempool-aware
  `listutxos`/`getnonce`, remote-attach mode over a live daemon's JSON-RPC,
  `--p2p-host` binding and graceful port-clash degradation, the deleted
  orphaned UI staying deleted, and no phrase over HTTP even for unencrypted
  wallets.
* **Integration** (`test_integration.py`) — boots the real daemon, mines past
  maturity, settles transfers and exercises the RPC surface.

Three developer checks drive real daemons over real sockets, plus the
full-mesh UI check:

```bash
python3 tools/web_smoke.py          # web suite: HTTP routes, CLI mirror, mine+send
python3 tools/e2e_check.py          # two regtest daemons, P2P sync, send, reindex, auth
python3 tools/e2e_three_nodes.py    # 3 CLI nodes + web UI node mesh, both directions,
                                    # remote-attach UI, regtest AND testnet profiles
python3 tools/network_check.py      # a real daemon per network: mainnet, testnet,
                                    # regtest - genesis, RPC surface, mining where
                                    # possible, preflight, clean RPC shutdown
python3 tools/wp_conformance.py     # every value the whitepaper pins, vs this build
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
  resync. Lock ordering is strictly `mempool` → never `chain`, so an RPC
  thread and the event loop cannot deadlock against each other.
* **RPC** — loopback by default, optional Basic auth, batch support, spec
  error semantics, a per-connection rate limit, a read-only GET surface,
  same-origin CORS, and no signing or key storage on the node. Proof-of-work
  search for `generate` runs in a worker thread so it cannot block the event
  loop.
* **Wallet** — AES-256-GCM with 600,000 PBKDF2-HMAC-SHA3-512 iterations
  (configurable; 60,000 files still read), 0600 permissions, atomic
  `mkstemp`+rename with a directory fsync, network **and** HRP binding, a
  bounded KDF/derivation index, and a persisted next-address index whose
  write failures are fatal rather than silent.
* **HTTP surfaces** — no wildcard CORS, one response per request, bounded
  bodies and query parameters, socket timeouts, and a per-subcommand command
  allowlist that keeps key-material and database-rewriting verbs off the
  web API.
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

* ML-DSA-87 is FIPS 204 conformant; hedged (randomised) signing is the
  default at every layer, including the low-level `fips204.sign()`, whose
  parameter default and documentation now agree. Deterministic signing is
  opt-in.
* Wallets are sealed with AES-256-GCM + PBKDF2-HMAC-SHA3-512, with a fresh
  salt and GCM nonce on every write. A documented SHA3-512 keystream fallback
  with encrypt-then-MAC exists for cryptography-free environments and is
  clearly flagged in the file.
* The wallet never builds a transaction the node would reject: one input per
  address, contiguous sweep nonces, every sweep fee above the relay floor,
  and `sign_transaction` restricted to single-input transactions (signing a
  multi-input transaction with one key would overwrite the other inputs'
  public keys).
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
* Change outputs default to fresh derived addresses (whitepaper 6.1), and the
  change-address index is persisted *before* broadcast so an address that
  reached the network is never re-issued.
* Neither the JSON-RPC port nor the web suite sends a wildcard CORS grant,
  and neither exposes a mutating method over `GET`. The web API additionally
  refuses to arm a solo miner on mainnet and keeps key-material and
  database-rewriting subcommands off HTTP entirely.
* **Peer admission is bounded before the handshake**: at most
  `MAX_PEERS` (64) connections in total, at most `MAX_PEERS_PER_IP` (4)
  inbound ones per remote address, and `RESERVED_OUTBOUND_SLOTS` slots kept
  for outbound dials so an inbound flood cannot lock the node out of the
  network it is syncing. A refused connection costs one accept and one close —
  no Peer object, no writer task, no frame buffer.
* **Header batches are validated before they are trusted**: a `headers`
  message must be a contiguous, PoW-valid chain rooted in a block the node
  already holds, and the peer's advertised height is taken from that chain
  rather than from the number of headers it sent. Otherwise a single frame
  could aim the sync driver at an arbitrary chain and pin the node in a
  permanent "syncing" state.
* **The listeners are exclusive on Windows.** `SO_REUSEADDR` there permits a
  second local process to bind the same port, which would let it answer the
  operator's `stop` / `startminer` / `sendrawtransaction` calls instead of the
  node; Qeuph binds `SO_EXCLUSIVEADDRUSE` for the P2P, JSON-RPC and web
  listeners (`qeuph/network/listen.py`) and detects "port in use" on every
  platform's errno, so a clash is reported with the port to change rather than
  silently shared or silently relocated.
* `Transaction.sign` requires exactly one key per input: a shorter list used
  to be silently truncated by `zip`, producing a transaction that looked
  signed in every log line and that no node would accept.

---

## License

MIT — acknowledging the QRL project whose node architecture this codebase
ports. See [LICENSE](LICENSE).

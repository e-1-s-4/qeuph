# Qeuph protocol specification

This document pins the on-chain byte formats and consensus rules. It is the
normative companion to the whitepaper; the reference implementation in
`qeuph/` enforces every rule listed here, and `tests/test_whitepaper.py`
asserts the pinned constants.

## Units

* `quphi` — atomic unit. 1 QUH = 100,000,000 quphi (8 decimals).
* Values are unsigned 64-bit integers in quphi.
* Output values must be **strictly greater than the dust threshold**
  (1,000 quphi) in both relay and block validation, so the UTXO set cannot be
  filled with uneconomic entries.

## Hashing

`dhash(x) = SHA3-512(SHA3-512(x))` — used for transaction ids, block ids,
the Merkle tree, address hashes, PoW and the wire checksum.

No SHA-2 and no elliptic-curve operation appears anywhere in the consensus
path.

## Addresses

```
pk        = ML-DSA-87 public key               (2592 bytes)
addr_hash = dhash(pk)                          (64 bytes)
address   = bech32m("quh", addr_hash)          ("quh1...", 113 chars)
```

Network HRPs: `quh` (mainnet), `tquh` (testnet), `rquh` (regtest). A wallet
file records the network and HRP it was created for; opening it with a
different `--network` is refused, because the HRP change would make every
balance lookup silently return zero.

Qeuph addresses are 113 characters, above BIP-350's 90-character limit. The
limit is raised to 200 rather than truncating the 512-bit digest. BIP-350's
error-detection guarantee holds for every length up to 1023, so nothing is
lost: a single-character substitution anywhere in the address is rejected
with probability > 0.99 (asserted in the test suite).

## Transactions

```
tx := version(4 LE)
     in_count(4 LE)
     input*
     out_count(4 LE)
     output*
     lock_time(8 LE)

input (non-coinbase) :=
     prev_txid(64)            dhash of the funding transaction
     prev_index(4 LE)
     txnonce(8 LE)            per-address sequential counter
     pubkey_len(2 LE)         always 2592
     pubkey(2592)             ML-DSA-87 public key owning the UTXO
     sig_len(2 LE)            always 4627
     signature(4627)          ML-DSA-87 signature

input (coinbase pseudo-input) :=
     prev_txid(64 zero bytes)
     prev_index(0xFFFFFFFF)
     txnonce(8 LE)            = block height (BIP-34 style)
     data_len(2 LE)           <= 256
     data(data_len)           miner data (extra nonce; the genesis message)

output := value(8 LE quphi) addr_hash(64)
```

* `txid = dhash(serialize(tx))`.
* The message signed by input *i* is `dhash(sigless(tx)) || LE32(i)` where
  `sigless(tx)` is the serialization with every signature field empty (public
  keys stay committed). Every signature therefore commits to the whole
  transaction, including the other inputs and their public keys.
* Fees = sum(inputs) − sum(outputs) ≥ 0.
* Validation per input: UTXO exists, `prev_index < 512`, coinbase maturity
  ≥ 100 blocks, `dhash(pubkey) == utxo.addr_hash`, `txnonce ==
  chain_nonce(addr)+1`, ML-DSA-87 signature verifies.
* Bounds: ≤ 512 inputs, ≤ 512 outputs, ≤ 400,000 bytes, `version == 1`.
* **One input per address per transaction.** The txnonce rule is per
  address, so a transaction spending two outputs of the same address would
  require the same address to present two different nonces equal to
  `chain_nonce+1`. Such a transaction is rejected. This constrains the
  *wallet* as much as the network: `wallet send` funds from a single address
  and therefore may spend exactly one of its outputs, so an amount above the
  largest single output is refused with an explicit message pointing at
  `sweep`, rather than assembled into a transaction every node would reject.
  `wallet sweep` chains one transaction per output with contiguous nonces
  `n, n+1, …`; an output too small to cover the relay fee is skipped, and
  because the nonce is advanced per *emitted* transaction, skipping one
  leaves no gap.
* Lock time (Bitcoin semantics): a non-zero `lock_time` makes the
  transaction non-final until either the chain height reaches it
  (`lock_time < 500,000,000`) or the median time past of the last 11
  blocks reaches it. Coinbase transactions are always final.
* **Coinbase maturity** is `height − cb_height ≥ 100`, matching
  `validate_tx` exactly. The `confirmations` shown by the RPC and the web UI
  is the display value `height − cb_height + 1`, which is one larger; the
  `mature` flag always follows the consensus expression, so a wallet can
  never build a transaction the node would reject.

### Unsigned transactions

`Transaction.deserialize` accepts an `allow_unsigned` flag used only by
tooling (`decoderawtransaction`, `wallet verify`, `wallet sign`), which permits
zero-length pubkey/signature fields. Consensus paths — blocks, the mempool,
relay — never set it: a block input must carry a full ML-DSA-87 key and
signature.

## Blocks

```
header := version(4 LE) prev_hash(64) merkle_root(64)
          timestamp(8 LE) bits(4 LE) height(8 LE) nonce(16 LE)     -- 168 bytes
block  := header tx_count(4 LE) (tx_len(4 LE) tx)*
```

* `block hash = dhash(header)`.
* Merkle root over txids (pairwise dhash; odd level duplicates the last).
* PoW: hash as big-endian integer < target decoded from `bits` (compact
  BTC-style, unsigned 24-bit mantissa over the 512-bit space).
  `bits` must lie in `[0x01010000, 0x407FFFFF]`; note that in compact form a
  **larger** value is an **easier** target, so the easiest bound is
  numerically the larger one.
* A 24-bit mantissa cannot express an arbitrary 512-bit target, so
  `target_to_bits` truncates: the encoded target is always ≤ the ideal value
  (never easier than requested), by at most 1 part in 2^18. Every node
  computes this identically.
* Block size limit: 2,000,000 bytes serialized; ≤ 20,000 transactions.
* Parsing is strict: a trailing byte, a zero transaction count, a
  zero-length transaction or a truncated field is a hard error.
* The first transaction must be the coinbase, and it must be the only
  coinbase; its `txnonce` must equal the block height; it must carry no
  pubkey or signature; its output total must not exceed
  `reward(height) + fees(block)`.
* No transaction id may appear twice in the same block.
* Every block's `bits` must equal the value the retarget controller derives
  from the chain it is extending.

## Difficulty

* 5-minute block time; retarget every 2048 blocks, i.e. when the **child**
  height is a multiple of 2048.
* `new_target = parent_target * actual_span / expected_span`, clamped to
  [parent/4, parent*4], all integer math (multiply first). The compact
  truncation of the result never makes the network easier than the clamp.
* Following the Bitcoin convention, `actual_span` is measured across the
  `retarget_interval` timestamps of the window (so `interval − 1`
  inter-block gaps) and `expected_span = (interval − 1) * block_time`.
* Timestamps must not decrease; at most 2 h in the future.

## Reward ("two-thirding")

```
epoch(h)  = h // 210000
reward(h) = floor(50 QUH * (2/3)^epoch)     [iteratively floored per epoch]
```

The floor is applied **at every epoch**, not once at the end: the series is
iterated, exactly as Bitcoin iterates its halvings. This is what makes the
total exact.

| epoch | start height | reward (QUH) | cumulative (QUH) |
|---|---|---|---|
| 0 | 0 | 50.00000000 | 10,500,000.000 |
| 1 | 210,000 | 33.33333333 | 17,499,999.999 |
| 2 | 420,000 | 22.22222222 | 22,166,666.666 |
| 3 | 630,000 | 14.81481481 | 25,277,777.776 |
| 4 | 840,000 | 9.87654320 | 27,351,851.848 |
| 5 | 1,050,000 | 6.58436213 | 28,734,567.895 |
| 10 | 2,100,000 | 0.86707648 | 31,135,827.851 |
| 20 | 4,200,000 | 0.01503642 | 31,493,684.651 |
| 53 | 11,130,000 | 0.00000001 | 31,499,999.859 |
| 54 | 11,340,000 | 0 | 31,499,999.859 |

Exact total emission: **3,149,999,985,930,000 quphi (31,499,999.8593 QUH)**,
which is 14,070,000 quphi (0.1407 QUH) below the 31,500,000 QUH cap. The
analytic bound `3 × 50 QUH × 210,000 = 31,500,000 QUH` can never be reached
because of the per-epoch floor.

> **Discrepancy note.** Table 5 of the whitepaper lists 0.86616069 for epoch
> 10 and 0.00014994 for epoch 20. Those two cells are typos: the iterated
> floor yields 0.86707648 and 0.01503642, and it is those values that
> reproduce the paper's *own* stated total (31,499,999.8593 QUH) and its
> "0.1407 QUH below the cap" claim in section 4.4. A closed-form
> `floor(50e8 · (2/3)^k)` (single floor at the end) gives
> 31,499,999.9349 QUH, which does not match either. The implementation
> follows the iterative rule the paper describes in prose, because that is the
> only reading consistent with its own arithmetic. The genesis, the total
> emission and the 31.5M cap are unaffected by the two misprinted cells.

## Mempool policy

* Minimum relay fee: 1,000 quphi per 1,000 bytes.
* Capacity: 200 MB, evicting the lowest fee-per-byte transactions first.
* Expiry: transactions older than 3 days are swept.
* An in-mempool ancestor chain may not exceed 25 pending transactions.
* Per-address nonce chaining is enforced by validating against the chain state
  overlaid with the pending pool, so a transaction with nonce *n+1* cannot
  enter the pool before the one with nonce *n*.
* The pool exposes its pending-spends overlay to the wallet surfaces:
  `listutxos`/`listunspent` hide outpoints spent by a pooled transaction,
  and `getnonce` returns `max(chain nonce, pending nonce)`, so a second
  payment can be built and chained while the first is still unconfirmed
  (a blind chain-state listing made every rapid second send fail with a
  confusing "missing UTXO" / "out-of-order nonce" rejection).
* Block templates are ranked by the fee-per-byte cached at admission time
  (the overlay mutates, so fees cannot be recomputed later).
* **Lock ordering.** The mempool never calls into the chain while holding
  `mempool.lock`. `median_time_past()` takes `chain.lock`, and
  `consider_reorg()` holds `chain.lock` while invoking the reorg callback
  that takes `mempool.lock`; resolving the height and MTP *before*
  acquiring `mempool.lock`, and having callers such as `_block_template`
  select from the mempool *before* taking `chain.lock`, keeps the two
  locks strictly ordered (`mempool` → never `chain`).

## Fork choice

Most cumulative work (`cum_work(block) = cum_work(parent) + 2^512/target + 1`).
Every stored block carries its 64-byte big-endian cumulative work, so the
main chain tip is the stored block with the highest cumulative work, **at any
depth** — a heavier side chain always activates.

Reorganisation re-validates the candidate chain block-by-block against a
scratch state (its own difficulty retarget history, checkpoints, full
transaction validation) before committing anything; an invalid side chain is
discarded. The commit is a single store transaction that rewrites the
canonical index and the full UTXO/nonce tables; if it fails, the previous
chain survives untouched.

A reorganisation **replaces the `ChainState` object**. Every collaborator
(mempool, RPC, miner) therefore reaches the state through `chain.state` or
`chain.state_provider()` and never caches the object it saw at construction
time. The mempool detects the identity change and re-validates its contents.

Orphan blocks (unknown parent) are held in a bounded in-memory pool
(128 blocks, 20-minute expiry), have their PoW checked before being held, and
resolve when the parent arrives.

## Persistence

SQLite in WAL mode, `synchronous=FULL`. Every state transition — genesis
initialisation, connecting a block, reorganising — is written in **one**
transaction, with the `meta.tip` / `meta.tip_height` pointers advanced last
inside that same transaction. A crash at any point therefore leaves the store
on a block boundary.

On load the canonical index is re-verified: genesis-anchored, contiguous, and
with intact parent links. A damaged index triggers a replay that rebuilds the
UTXO/nonce tables by re-applying the canonical blocks and truncates to the
last provable block. A data directory that holds a chain with a DIFFERENT
genesis (e.g. a testnet daemon pointed at a regtest directory) is refused
with a clear operator-facing error instead of being replayed into a crash.

## P2P wire format

```
frame := magic(4) command(12 NUL-padded) length(4 LE)
         checksum(4: dhash(payload)[:4]) payload(JSON, length bytes)
```

Magic is per network: `QUH!` (mainnet), `TQH!` (testnet), `RQH!` (regtest), so
a peer on another network is rejected by the frame reader before any parsing.

Commands: `version`, `verack`, `getheaders`, `headers`, `getblocks`,
`block`, `inv`, `getdata`, `notfound`, `tx`, `mempool`, `ping`, `pong`,
`getaddr`, `addr`.

Payloads are JSON documents; binary data is hex-encoded. The frame reader is
bounded (32 MB per peer) and resynchronises on the magic, so a corrupt frame
is skipped rather than desynchronising the stream.

* **Handshake** — each side sends `version` (network, protocol version, user
  agent, height, tip hash, timestamp) and answers `verack`. A network
  mismatch is an immediate disconnect **and a ban**; a protocol version below
  the minimum disconnects; a gross clock skew (> 7 days) is penalised.
* **Admission limits** — every connection is admitted *before* the handshake
  and is refused with a closed socket when it would exceed: the
  `MAX_PEERS` ceiling (64), the inbound cap (`MAX_PEERS` −
  `RESERVED_OUTBOUND_SLOTS`, so a flood of inbound sockets can never stop the
  node from dialling the peers it needs), or `MAX_PEERS_PER_IP` (4) inbound
  connections from one address. Refusing early means a connection flood costs
  one accept and one close instead of a socket, a writer task and a frame
  buffer each.
* **Header batches must be rooted and contiguous.** A `headers` message is
  only used for block requests when the first header extends a block we
  already hold, every later header extends its predecessor at the next
  height, and every header satisfies its own proof of work; otherwise the
  peer is scored and disconnected. The peer's advertised height comes from
  the chain it just proved it has, not from the number of unseen headers it
  sent. Without those rules an unsolicited `headers` frame could aim the sync
  driver at an arbitrary chain and keep the node permanently "syncing".
* **IBD** — headers-first with a sparse block locator (last 11 hashes, then
  exponentially sparser) and a continuous sync driver with stall detection:
  blocks requested but not delivered within 30 s are re-requested. Block
  requests are batched (64 per `getdata`) and at most 16 in flight, so a peer
  cannot make the node ask for thousands of 2 MB blocks at once.
* **Relay** — inv/getdata, non-blocking per-peer queues, and `notfound`
  replies so a requester stops waiting for an item the peer does not have.
* **Housekeeping** — `getaddr`/`addr` on connect, keepalive `ping`/`pong`
  every 30 s, idle pruning after 180 s, periodic redial toward
  `TARGET_OUTBOUND_PEERS`, and a bounded known-address cache.
* **Peer scoring** — a token-bucket rate limit (600 msg/s, burst 1500) and a
  misbehaviour score (decaying at 1 point/second) that bans a peer for 24
  hours at 100 points. The ban table is persisted, so a ban survives a
  restart. Address floods (> 128 new addresses in one message) are an
  immediate disconnect.

## JSON-RPC

JSON-RPC 2.0 over HTTP on port 19091 (mainnet), loopback by default.
`POST` takes a document or a batch array; `GET /?method=…&params=…` serves
**read-only** calls only. Application errors are returned as `error` objects
with **HTTP 200**, as the specification requires; only transport faults (bad
auth, oversized body, unparseable body) use 4xx. Optional HTTP Basic auth via
`--rpc-user` / `--rpc-password`.

Transport rules:

* **GET is read-only.** A mutating method over GET is refused with
  `-32600`. A GET is what a link, an `<img>` tag and a cross-origin fetch
  all issue, so an unauthenticated read-only endpoint must not also be a
  node-control and DoS primitive.
* **CORS is same-origin.** The wildcard `Access-Control-Allow-Origin: *` is
  not sent; the request's own `Origin` is echoed only when it matches the
  `Host` being served. Browsers reach loopback freely, so a wildcard grant
  on a surface that can mine, submit blocks and stop the node lets any page
  the operator visits drive it.
* **Rate limiting.** Each connection gets a 120 call/second token bucket
  (1-second window) and receives HTTP 429 with `Connection: close` when it is
  exhausted. `getmininginfo` alone performs 20,000 double-SHA3-512 hashes, so
  an unbounded call rate is a real CPU sink.
* **Bodies** are capped at 1 MiB. A rejected body is read and discarded
  (up to 8 MiB) and the connection is then closed, so the client receives a
  clean status code instead of a reset caused by unread bytes.
* **Auth failures** drain the body and answer `401` with
  `Connection: close`; a malformed or non-ASCII `Authorization` header is
  treated as a failed authentication rather than an exception.
* **The listener is exclusive on Windows.** `http.server.HTTPServer` binds
  with `SO_REUSEADDR`, which on Windows means "other processes may bind this
  address too" rather than POSIX's "reuse a TIME_WAIT address": a second
  local process could take the RPC port and impersonate the node, answering
  the operator's `stop` / `startminer` / `sendrawtransaction` calls while the
  real node stopped serving. Qeuph binds `SO_EXCLUSIVEADDRUSE` on Windows
  (same for the P2P and web listeners, via `qeuph.network.listen`) and keeps
  the stdlib behaviour everywhere else. "Port in use" is detected on every
  platform (`EADDRINUSE` 98/100, `WSAEADDRINUSE` 10048, `WSAENOPORT` 10049,
  `WSAEACCES` 10013); the daemon then says exactly which port to change.

Block generation (`generate`, regtest/testnet only) is scheduled on the
node's event loop so RPC threads never race consensus state; the
proof-of-work search runs in a worker thread, because a synchronous search
on the event loop would stop the node servicing P2P and mempool traffic for
its whole duration. `startminer` is likewise refused on mainnet — the daemon
owns the solo miner there (`node --mine ADDR`).

`rescan` no longer holds `chain.lock` around a full-chain re-validation,
which previously froze every other RPC reader and the event loop.

The node deliberately implements **no signing and no key storage**: the RPC
surface is a remote-control surface for the chain, and keeping private keys
off it removes a whole class of exposure. Use `qeuph wallet` for anything that
touches keys. See README.md for the method list.

## Web suite

`python -m qeuph.web.server` (equivalently `npm run start`, or `qeuph web`)
serves a node explorer on 127.0.0.1:3000. Its contract:

* reads go through `/api/*` views;
* chain writes go through `POST /api/rpc`, the same `RPCService.dispatch`
  the daemon exposes;
* commands go through `POST /api/cli` and `POST /api/wallet`, which execute
  the literal `qeuph` subcommands in-process, and `GET /api/cli` returns the
  live argparse tree so the UI cannot offer an option the CLI lacks;
* the master seed and the 24-word recovery phrase are **never** returned:
  `wallet mnemonic`, `wallet backup --out-mnemonic` and `--show-seed` are
  refused by the web route, phrase/seed/secret-key-shaped text is redacted
  from any CLI output before it leaves the process, the `argv` echoed
  back in the response has `--passphrase` / `--from-mnemonic` values masked,
  the wallet info view never contains a phrase (even for an unencrypted
  wallet file), a GET of the wallet info never CREATES a wallet, and the
  create/restore responses never echo a phrase (restore is the only flow
  that accepts one, and it is never reflected back);
* the bind address is loopback unless `--allow-remote` is passed (decided
  with `ipaddress.is_loopback`, so `localhost` and `127.0.0.2` are accepted
  and `""` / `0.0.0.0` are not), and the embedded node runs regtest by
  default with the miner controls disabled on mainnet;
* the embedded node RUNS P2P (loopback-bound unless `--p2p-host` says
  otherwise): it dials every `--connect HOST:PORT` target, accepts inbound
  connections from CLI daemons, and syncs/relays like any `qeuph node`, so
  a UI node and a CLI node are interchangeable mesh members;
* with `--embedded-node off --remote-rpc URL` the suite becomes a thin
  client of an EXTERNAL daemon: every chain view is served from that node's
  JSON-RPC, the RPC console forwards to it, miner/generate/network-switch
  routes are refused, wallet reads still derive addresses locally, and
  wallet sends sign locally and hand the remote node only the signed
  transaction (`sendrawtransaction`); `chain` CLI-bridge commands are
  refused because they would read the local (empty) database and lie about
  the attached node.

Command surface. The allowlist is a group *and* a per-subcommand set, so
the HTTP surface cannot reach the dangerous verbs:

| route | allowed |
|---|---|
| `POST /api/cli` | `chain info\|blocks\|block\|tx\|verify`, `genesis`, `emission`, `address`, `crypto`, `version` |
| `POST /api/wallet` | `show`, `balance`, `addresses`, `newaddress`, `send`, `sweep`, `verify`, `utxos`, `create` |

Excluded, with reasons:

* `node` / `web` — a second daemon on the same data directory, or a nested
  web server.
* `rpc` — `--url` is an arbitrary outbound URL, so allowing it turned this
  endpoint into an SSRF primitive; the browser already has `POST /api/rpc`.
* `mine` — an unbounded CPU and thread burner reachable without a flag.
* `chain truncate` / `chain reindex` — they rewrite or destroy the embedded
  node's database; that is a node-state mutation, not a browser command.
* `wallet sign` / `passwd` / `backup` / `restore` / `mnemonic` — key
  material, and `backup --out` / `sign --out` are arbitrary file writes.

Transport rules mirror the JSON-RPC surface: same-origin CORS only, an 8 MiB
body cap answered with 413 and `Connection: close` (body drained), a
120-second socket timeout, bounded `limit`/`count` query parameters
(`?limit=abc` is a 400, not a 500), a 32-call cap on `/api/rpc` batches, and
exactly one HTTP response per request — route helpers raise `HttpError`
rather than writing an error response from inside a `send_json` wrapper,
which previously emitted two complete responses on one keep-alive connection.
In-process CLI runs are serialised with a lock, because
`redirect_stdout`/`redirect_stderr` mutate process-global state, and
`sys.stdin` is replaced so a subcommand can never block on a `getpass`
prompt inside a worker thread.

## Wallet keystore

The master seed is sealed with AES-256-GCM under a PBKDF2-HMAC-SHA3-512 key
(`dklen=32`), with a fresh 32-byte salt and 12-byte GCM nonce on every save.
`cryptography` is optional; without it a documented SHA3-512 keystream XOR
with encrypt-then-MAC is used and flagged in the file.

* **Iteration count.** The shipped default is **600,000** (file `version` 2);
  `version` 1 files declaring 60,000 still open, and
  `$QEUPH_WALLET_KDF_ITERATIONS` overrides the default for new files.

  > **Deviation from the whitepaper, deliberate.** Appendix text specifies
  > "PBKDF2-HMAC-SHA3-512 with 60,000 iterations". The implementation ships
  > 600,000 for new wallets, ten times the paper's figure, and reads the
  > older 60,000 files unchanged. Raising the work factor is a local,
  > non-consensus choice: the iteration count is recorded per file and
  > covered by the AEAD tag, so it never affects chain validity or
  > interoperation, and a v1 wallet opens on any build. The 60,000 figure
  > remains supported rather than deprecated.

* **Integrity of the metadata.** The salt and iteration count are
  authenticated implicitly (changing either changes the derived key and
  fails the GCM tag). `network` and `hrp` are read back and validated on
  open: a file whose network or address prefix does not match the requested
  one is refused rather than silently reporting zero balances, and both
  fields must be consistent.
* **Bounded inputs.** The KDF iteration count read from the file is clamped
  to `60,000 .. 10,000,000` and the persisted `next_index` to
  `0 .. 2^32-1`. PBKDF2 is deliberately slow and the index drives a keygen
  loop, so an implausible value in a truncated or hand-edited file would
  otherwise hang every open.
* **Writes.** The file is written through a `mkstemp` temp file in the same
  directory (mode 0600, no symlink following, no name collision between
  concurrent writers), fsynced, atomically renamed, and the parent directory
  is fsynced so the rename is durable. The directory is created 0700.
* **Persisted index.** `next_index` is written back after every derived
  address, and a failed write is a hard error rather than a silent one: a
  swallowed failure would re-issue an address on the next run, which is
  exactly the rotation guarantee the index exists to provide.
* **Signing is hedged by default.** `fips204.sign()` defaults to the
  randomised FIPS 204 variant, matching its own documentation; deterministic
  signing is opt-in via `deterministic=True`.

## Genesis

Mainnet genesis: timestamp 1790812800 (2026-10-01 00:00:00 UTC), bits
`0x3D0FFFFF`, message

```
26/Sep/2026 The quantum era demands quantum-resistant money. Qeuph:
ML-DSA-87 + SHA3-512, two-thirding to 31.5M QUH.
```

The coinbase pays 0 quphi to the null address `dhash(b"")`, and the winning
nonce 355026620 is pinned in `qeuph/core/genesis.py`. The block hash

```
0000000d2f105b239cd085e9d4bd7fa087dc6a085ee37b3842d539ab9c974247
fa8c4000695807b0a5d306d40c713e32b130387f72b64a00bf2b0c9953b179b1
```

is reproduced deterministically by every node and is also recorded in
`constants.CHECKPOINTS[0]`. `qeuph genesis` rebuilds and verifies it.

## Launch parameters an operator must set

* `qeuph.constants.BOOTSTRAP_NODES_MAINNET` — or pass `--connect host:port`.
* `qeuph.constants.DNS_SEEDS_MAINNET` — at least one published seed.
* `qeuph.constants.CHECKPOINTS` — add periodic heights as the chain grows;
  a mismatch at a checkpointed height is a hard consensus error and bounds how
  far a compromised peer can reorganise the chain.

The daemon logs a warning at startup when mainnet is configured with no peers
and no seeds.

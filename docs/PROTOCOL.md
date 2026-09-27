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
  `chain_nonce+1`. Such a transaction is rejected; `wallet sweep` therefore
  chains one transaction per output with nonces `n, n+1, …`.
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
* Block templates are ranked by the fee-per-byte cached at admission time
  (the overlay mutates, so fees cannot be recomputed later).

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
last provable block.

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
read-only calls. Application errors are returned as `error` objects with
**HTTP 200**, as the specification requires; only transport faults (bad
auth, oversized body, unparseable body) use 4xx. Optional HTTP Basic auth via
`--rpc-user` / `--rpc-password`.

Block generation (`generate`, regtest/testnet only) is scheduled on the
node's event loop so RPC threads never race consensus state. See README.md
for the method list.

The node deliberately implements **no signing and no key storage**: the RPC
surface is a remote-control surface for the chain, and keeping private keys
off it removes a whole class of exposure. Use `qeuph wallet` for anything that
touches keys.

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
  refused by the web route, and phrase/seed-shaped text is redacted from any
  CLI output before it leaves the process;
* the bind address is loopback unless `--allow-remote` is passed, and the
  embedded node runs regtest by default with the miner controls disabled on
  mainnet.

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

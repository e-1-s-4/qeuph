# Qeuph (QUH)

A complete, quantum-resistant cryptocurrency node suite.  Qeuph is a hybrid
port of the [QRL](https://github.com/theQRL/QRL) (Quantum Resistant Ledger)
architecture — the first serious post-quantum ledger — rebuilt around:

# Whitepaper
https://drive.google.com/file/d/1fTAz37Bgkw51UXLaEQ6ZJWVhvhO92wPc/view?usp=sharing

| Property | Value |
|---|---|
| Signatures | **ML-DSA-87** (FIPS 204, NIST Category 5) |
| Hashing | **double SHA3-512** (tx ids, block ids, addresses, PoW) |
| Addresses | **Bech32m** (BIP-350), HRP `quh`, 512-bit payload |
| Consensus | **Pure proof of work** (SHA3-512), 5 minute blocks |
| Difficulty | retarget every **2048 blocks** (~7.1 days), bounded ±4x |
| Reward | **50 QUH × (2/3)^epoch**, floored, every 210,000 blocks |
| Supply | 31,500,000 QUH cap (exact emission 31,499,999.8593 QUH) |
| Divisibility | 8 decimals — 1 QUH = 100,000,000 **quphi** |
| Transactions | **UTXO + txnonce** hybrid |
| Coinbase maturity | 100 blocks |
| Block size | 2 MB |
| Ports | P2P 19090, JSON-RPC 19091 (mainnet) |

The full node suite includes: the node daemon with P2P sync and relay, a
solo miner, an encrypted wallet, a JSON-RPC service, and a CLI — plus a
pure-Python FIPS 204 reference implementation cross-verified against
OpenSSL's ML-DSA.

## Quick start

```bash
# run a full node on mainnet
python -m qeuph.cli.main node --network mainnet

# solo mine to your address
python -m qeuph.cli.main node --network mainnet --mine quh1...

# create a wallet (encrypted with a passphrase)
python -m qeuph.cli.main wallet create --network mainnet

# show addresses + balances (node must be running)
python -m qeuph.cli.main wallet show --rpc http://127.0.0.1:19091/

# send funds
python -m qeuph.cli.main wallet send --to quh1... --amount 1.5 \
    --fee 0.01 --rpc http://127.0.0.1:19091/

# inspect the chain offline
python -m qeuph.cli.main chain info --network mainnet
python -m qeuph.cli.main emission          # the two-thirding schedule
```

For fast iteration / testing use `--network regtest` (instant mining) or
`--network testnet`.

## Genesis

Mainnet genesis (timestamp 2026-10-01 00:00:00 UTC, bits `0x3D0FFFFF`,
nonce 355026620):

```
0000000d2f105b239cd085e9d4bd7fa087dc6a085ee37b3842d539ab9c974247
fa8c4000695807b0a5d306d40c713e32b130387f72b64a00bf2b0c9953b179b1
```

After installation (`pip install .`) the entry point is simply `qeuph`.

## JSON-RPC

The node exposes JSON-RPC 2.0 at `http://127.0.0.1:19091/`:

```bash
curl -s localhost:19091 -d '{"jsonrpc":"2.0","id":1,
  "method":"getblockchaininfo","params":{}}' | python -m json.tool
```

Methods: `getblockchaininfo`, `getblockhash`, `getblock`, `gettransaction`,
`getmempoolinfo`, `getmempool`, `sendtransaction`, `getbalance`,
`listutxos`, `getnonce`, `getpeerinfo`, `getrewardinfo`, `startminer`,
`stopminer`, `getmininginfo`, `stop`.

## Cryptography

* **Signatures** — ML-DSA-87 per FIPS 204 (final).  `qeuph/crypto/fips204.py`
  is a dependency-free reference implementation of Algorithms 5-48 and has
  been cross-verified against OpenSSL/AWS-LC (`cryptography` >= 45):
  seeded keygen produces byte-identical public keys, and each backend
  verifies the other's signatures.  When the fast backend is available it
  is used automatically (~50,000 signatures/s vs ~20/s pure-Python).
* **Addresses** — `bech32m("quh", SHA3-512(SHA3-512(pk)))`.  The full
  64-byte digest is kept as the address payload, so address collisions
  are a 512-bit hash problem even for quantum adversaries.
* **PoW** — block hash = double SHA3-512 over the 168-byte header; valid
  when the hash as a big-endian integer is below the compact `bits` target.

## Transaction model (UTXO + txnonce)

Transactions spend unspent transaction outputs.  Every input additionally
carries a **txnonce**: the per-address strictly-increasing counter of the
whitepaper.  A transaction is valid when

```
input.txnonce == chain_nonce(address) + 1
```

which provides deterministic ordering and replay protection on top of the
UTXO model.  Each input carries an ML-DSA-87 signature over
`dhash(sigless-tx) || LE32(input_index)`; the signatureless digest commits
to every input's public key, all outputs, the lock time and every other
input's nonce.

## Two-thirding reward schedule

```
reward(h) = floor(50 QUH × (2/3)^floor(h / 210000))
```

| epoch | height | reward |
|---|---|---|
| 0 | 0 | 50 QUH |
| 1 | 210,000 | 33.33333333 QUH |
| 2 | 420,000 | 22.22222222 QUH |
| 3 | 630,000 | 14.81481481 QUH |
| ... | ... | ... |
| 53 | 11,130,000 | 0.00000001 QUH (1 quphi) |
| 54+ | — | 0 (fees only) |

At 5-minute blocks the schedule runs ~108 years and totals
31,499,999.8593 QUH — 0.1407 QUH under the 31.5M cap, Qeuph's analogue of
Bitcoin never quite reaching 21M.

## Repository layout

```
qeuph/
├── qeuph/
│   ├── constants.py config.py      network parameters
│   ├── crypto/                     fips204.py, ml_dsa.py, bech32m.py, address.py
│   ├── core/                       tx, block, chain, state, mempool,
│   │                               validation, difficulty, pow, reward, genesis
│   ├── db/store.py                 SQLite persistence (WAL)
│   ├── network/                    p2p protocol + JSON-RPC
│   ├── node/node.py                asyncio full node service
│   ├── services/miner.py           solo miner
│   ├── wallet/                     keys, keystore (AES-256-GCM), wallet
│   ├── main.py                     daemon wiring
│   └── cli/main.py                 command line interface
├── tests/                          79 tests incl. cross-crypto + integration
├── tools/mine_genesis.py           genesis PoW miner
└── docs/                           PORTING.md, PROTOCOL.md
```

## Testing

```bash
python -m pytest tests/ -q
```

The suite covers: FIPS 204 conformance and OpenSSL cross-verification,
bech32m vectors, transaction rules (signatures, txnonce ordering, replay,
maturity), block/PoW/difficulty, the reward schedule, wallet encryption,
mempool policy, chain reorg/persistence, and an end-to-end integration
test that boots the daemon, mines, and settles transfers through the RPC
surface.

## Security notes

* ML-DSA-87 is FIPS 204 conformant (hedged signing by default).
* Wallets are sealed with AES-256-GCM + PBKDF2-HMAC-SHA3-512 (60k
  iterations); a documented SHA3-keystream fallback exists for
  cryptography-free environments.
* The pure-Python FIPS 204 implementation is constant-time-*unfriendly*;
  side-channel hardened deployments should rely on the OpenSSL backend
  (this is the same guidance FIPS 204 gives for deterministic signing).
* Post-quantum signatures are large (4,627 B each): a 1-in-2-out Qeuph
  transaction is ~7.5 KB.  Block capacity and relay logic account for it.

## License

MIT — acknowledging the QRL project whose node architecture this codebase
ports.  See LICENSE.

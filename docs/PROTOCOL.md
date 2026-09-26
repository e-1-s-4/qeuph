# Qeuph protocol specification

This document pins the on-chain byte formats and consensus rules.

## Units

* `quphi` — atomic unit.  1 QUH = 100,000,000 quphi (8 decimals).
* Values are unsigned 64-bit integers in quphi.

## Hashing

`dhash(x) = SHA3-512(SHA3-512(x))` — used for transaction ids, block ids,
the Merkle tree, address hashes, PoW and the wire checksum.

## Addresses

```
pk        = ML-DSA-87 public key               (2592 bytes)
addr_hash = dhash(pk)                          (64 bytes)
address   = bech32m("quh", addr_hash)          ("quh1...", 113 chars)
```

Network HRPs: `quh` (mainnet), `tquh` (testnet), `rquh` (regtest).

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
     data(data_len)           arbitrary miner data (e.g. the genesis message)

output := value(8 LE quphi) addr_hash(64)
```

* `txid = dhash(serialize(tx))`.
* The message signed by input *i* is
  `dhash(sigless(tx)) || LE32(i)` where `sigless(tx)` is the serialization
  with every signature field empty (public keys stay committed).
* Fees = sum(inputs) - sum(outputs) >= 0.
* Validation per input: UTXO exists, coinbase maturity >= 100 blocks,
  `dhash(pubkey) == utxo.addr_hash`, `txnonce == chain_nonce(addr)+1`,
  ML-DSA-87 signature verifies.

## Blocks

```
header := version(4 LE) prev_hash(64) merkle_root(64)
          timestamp(8 LE) bits(4 LE) height(8 LE) nonce(16 LE)
block  := header tx_count(4 LE) (tx_len(4 LE) tx)*
```

* `block hash = dhash(header)`.
* Merkle root over txids (pairwise dhash; odd level duplicates the last).
* PoW: hash as big-endian integer < target decoded from `bits`
  (compact BTC-style, unsigned 24-bit mantissa over the 512-bit space).
* Block size limit: 2,000,000 bytes serialized.
* First transaction must be the coinbase; its output total must not exceed
  `reward(height) + fees(block)`.

## Difficulty

* 5-minute block time; retarget every 2048 blocks.
* `new_target = parent_target * actual_span / expected_span`, clamped to
  [parent/4, parent*4], all integer math (multiply first).
* Timestamps must not decrease; max 2h in the future.

## Reward ("two-thirding")

```
epoch(h)  = h // 210000
reward(h) = floor(50 QUH * (2/3)^epoch)     [iteratively floored]
```

Exact total emission: 3,149,999,985,930,000 quphi (31,499,999.8593 QUH).

## Fork choice

Most cumulative work (`sum(2^512 / target + 1)`).  Side-chain blocks are
stored; a reorganisation replays from the common ancestor.

## P2P wire format

```
frame := magic("QUH!" 4) command(12 NUL-padded) length(4 LE)
         checksum(4: dhash(payload)[:4]) payload(JSON, length bytes)
```

Commands: `version`, `verack`, `getheaders`, `headers`, `getblocks`,
`block`, `inv`, `getdata`, `tx`, `mempool`, `ping`, `pong`.
IBD is headers-first; relay is inv/getdata based.

## JSON-RPC

JSON-RPC 2.0 over HTTP POST on port 19091 (mainnet).  See README.md for
the method list.

## Genesis

Mainnet genesis: timestamp 1790812800 (2026-10-01 00:00:00 UTC), message
`"26/Sep/2026 The quantum era demands quantum-resistant money. Qeuph:
ML-DSA-87 + SHA3-512, two-thirding to 31.5M QUH."`, coinbase pays 0 to
the null address `dhash(b"")`, PoW at the initial mainnet bits.  The
winning nonce is pinned in `qeuph/core/genesis.py`; the block hash is
reproduced deterministically by every node.

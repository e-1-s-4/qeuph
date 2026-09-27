"""
Consensus validation rules for transactions and blocks.

Ported from QRL's validation spread across TransactionPool/ChainManager,
adapted to Qeuph's UTXO + txnonce model and ML-DSA-87 signatures.

Rules implemented (whitepaper sections 2 and 4, Appendix A):

  transaction
    * canonical version, at least one input and one output
    * size, input-count and output-count bounds
    * every referenced UTXO exists, is mature, and is owned by the input's
      ML-DSA-87 public key (address hash = double SHA3-512(public key))
    * txnonce == chain_nonce(address) + 1 for every input, so ordering and
      replay protection are deterministic per address
    * one valid FIPS 204 signature per input over
      dhash(sigless_tx) || LE32(input_index)
    * outputs are positive, of canonical size, above the dust threshold, and
      their sum does not exceed the sum of the inputs
    * optional minimum fee rate (mempool relay policy)
    * lock_time finality (Bitcoin semantics: height-locked below
      500,000,000, median-time-past-locked at or above it)

  block
    * header links to the parent (hash + height), known version
    * valid proof of work against the compact target
    * timestamp monotonic and at most 2 hours in the future
    * merkle root commits to exactly the block's transaction ids
    * serialized size within MAX_BLOCK_SIZE
    * first transaction is the coinbase, the only coinbase, embedding the
      height (BIP-34 style) and paying no more than reward + fees
    * every other transaction validates against the evolving state
    * difficulty must equal the value the retarget controller produces
    * no transaction id may appear twice in the same block

Lock time: a transaction with a non-zero lock_time is not final until either
the chain reaches height >= lock_time (when lock_time < 500,000,000) or the
median time of the last 11 blocks (MTP) >= lock_time (otherwise).  Coinbase
transactions are always final.
"""
from __future__ import annotations

import time
from typing import Optional, Set

from qeuph import constants as C
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.core.tx import MAX_COINBASE_DATA, Transaction

MAX_U64 = (1 << 64) - 1


class TxValidationError(Exception):
    pass


class BlockValidationError(Exception):
    pass


# Threshold separating block-height lock times from unix-time lock times.
LOCKTIME_THRESHOLD = 500_000_000


def tx_is_final(tx: Transaction, height: int, mtp: int) -> bool:
    """Bitcoin-style finality for the lock_time field."""
    if tx.lock_time == 0:
        return True
    if tx.lock_time < LOCKTIME_THRESHOLD:
        return height >= tx.lock_time
    return mtp >= tx.lock_time


# ---------------------------------------------------------------------------
# Transaction validation
# ---------------------------------------------------------------------------
def validate_tx(tx: Transaction, state, height: int,
                utxo_override=None, fee_rate: int = 0,
                mtp: Optional[int] = None,
                enforce_dust: bool = True) -> int:
    """Validate a non-coinbase transaction against `state`.

    `utxo_override`: optional {outpoint: UTXO} lookup used by the mempool
    to layer pending transactions onto the confirmed state.

    `height`: the height at which inclusion is being tested (block height
    when validating a block; chain height + 1 when admitting to mempool).

    `mtp`: median time past (used by lock time finality); None disables
    time-based lock time checks.

    Returns the fee (quphi).  Raises TxValidationError on any violation.
    """
    if tx.is_coinbase:
        raise TxValidationError("validate_tx: coinbase not allowed here")
    if tx.version != C.TX_VERSION:
        raise TxValidationError("unknown transaction version")
    if not tx.inputs:
        raise TxValidationError("no inputs")
    if not tx.outputs:
        raise TxValidationError("no outputs")
    if len(tx.inputs) > C.MAX_TX_INPUTS:
        raise TxValidationError("too many inputs")
    if len(tx.outputs) > C.MAX_TX_OUTPUTS:
        raise TxValidationError("too many outputs")
    if tx.size() > C.MAX_TX_SIZE:
        raise TxValidationError("transaction too large")
    if tx.lock_time >= MAX_U64:
        raise TxValidationError("lock_time out of range")
    if not tx_is_final(tx, height, mtp if mtp is not None else 1 << 62):
        raise TxValidationError(
            f"transaction locked until {tx.lock_time} "
            f"(height {height}, mtp {mtp})")
    for i, o in enumerate(tx.outputs):
        if o.value <= 0:
            raise TxValidationError(f"output {i} has non-positive value")
        if o.value > MAX_U64:
            raise TxValidationError(f"output {i} value out of range")
        if len(o.addr_hash) != C.ADDRESS_HASH_SIZE:
            raise TxValidationError(f"output {i} bad address hash size")
        if enforce_dust and o.value <= C.DUST_THRESHOLD:
            raise TxValidationError(
                f"output {i} value {o.value} is dust "
                f"(minimum {C.DUST_THRESHOLD + 1} quphi)")

    def lookup(txid, idx):
        if utxo_override is not None and (txid, idx) in utxo_override:
            return utxo_override[(txid, idx)]
        return state.get_utxo(txid, idx)

    total_in = 0
    seen: Set = set()
    nonces_seen: dict = {}
    for i, inp in enumerate(tx.inputs):
        op = (inp.prev_txid, inp.prev_index)
        if op in seen:
            raise TxValidationError("duplicate input")
        seen.add(op)
        if inp.prev_index >= C.MAX_TX_OUTPUTS:
            raise TxValidationError(f"input {i} output index out of range")
        u = lookup(inp.prev_txid, inp.prev_index)
        if u is None:
            raise TxValidationError(f"input {i} spends missing UTXO")
        # maturity
        if u.is_coinbase and (height - u.cb_height) < C.COINBASE_MATURITY:
            raise TxValidationError(f"input {i} spends immature coinbase "
                                    f"(needs {C.COINBASE_MATURITY} confirmations)")
        # pubkey must hash to the UTXO owner
        if len(inp.pubkey) != ml_dsa.PK_SIZE:
            raise TxValidationError(f"input {i} bad pubkey size")
        pk_hash = addr_mod.pk_to_hash(inp.pubkey)
        if pk_hash != u.addr_hash:
            raise TxValidationError(f"input {i} pubkey does not own UTXO")
        # one input per address inside a single transaction, otherwise the
        # per-address nonce rule would be self-contradictory
        if pk_hash in nonces_seen:
            raise TxValidationError(
                f"input {i} spends a second output of an address already "
                f"spending in this transaction")
        # txnonce: strictly the next value for that address
        expect = state.nonce_of(pk_hash) + 1
        if inp.txnonce != expect:
            raise TxValidationError(
                f"input {i} txnonce {inp.txnonce} != expected {expect} "
                f"(replay or out-of-order)")
        nonces_seen[pk_hash] = inp.txnonce
        # signature
        if len(inp.signature) != ml_dsa.SIG_SIZE:
            raise TxValidationError(f"input {i} bad signature size")
        if not ml_dsa.verify(inp.pubkey, tx.signing_message(i), inp.signature):
            raise TxValidationError(f"input {i} ML-DSA-87 signature invalid")
        total_in += u.value

    total_out = tx.total_out
    if total_out <= 0:
        raise TxValidationError("non-positive output total")
    if total_out > MAX_U64:
        raise TxValidationError("output total overflows uint64")
    fee = total_in - total_out
    if fee < 0:
        raise TxValidationError("outputs exceed inputs")
    if fee_rate > 0:
        min_fee = (tx.size() * fee_rate + 999) // 1000
        if fee < min_fee:
            raise TxValidationError(f"fee {fee} below minimum {min_fee}")
    return fee


def validate_coinbase(tx: Transaction, height: int, expected_reward: int) -> int:
    """Validate the coinbase of a block at `height`.  Returns fees claimed."""
    if not tx.is_coinbase:
        raise BlockValidationError("first transaction must be coinbase")
    if len(tx.inputs) != 1:
        raise BlockValidationError("coinbase must have exactly one pseudo-input")
    cb = tx.inputs[0]
    if cb.txnonce != height:
        raise BlockValidationError("coinbase must embed block height (BIP-34 style)")
    if len(cb.pubkey) or len(cb.signature):
        raise BlockValidationError("coinbase must not carry pubkey/signature")
    if len(cb.data) > MAX_COINBASE_DATA:
        raise BlockValidationError("coinbase data too long")
    if len(tx.outputs) > C.MAX_TX_OUTPUTS:
        raise BlockValidationError("coinbase has too many outputs")
    for i, o in enumerate(tx.outputs):
        if o.value <= 0:
            raise BlockValidationError("coinbase output non-positive")
        if o.value > MAX_U64:
            raise BlockValidationError("coinbase output value out of range")
        if len(o.addr_hash) != C.ADDRESS_HASH_SIZE:
            raise BlockValidationError("coinbase output bad address hash size")
    total = tx.total_out
    if total > MAX_U64:
        raise BlockValidationError("coinbase output total overflows uint64")
    if total > expected_reward:
        raise BlockValidationError(
            f"coinbase pays {total}, exceeds allowed {expected_reward}")
    return expected_reward - total   # fees left unclaimed


# ---------------------------------------------------------------------------
# Block validation
# ---------------------------------------------------------------------------
def _check_pow_safe(header_bytes: bytes, bits: int) -> bool:
    """check_pow, mapping malformed compact targets to validation failure."""
    from qeuph.core import pow as pow_mod
    try:
        return pow_mod.check_pow(header_bytes, bits)
    except ValueError:
        return False


def _check_header(block, prev_block, max_future: int,
                  current_time: Optional[int]) -> int:
    """Header-only rules shared by validate_block / validate_and_apply_block.

    Returns the current timestamp used for the future-bound check."""
    hdr = block.header
    if hdr.height != prev_block.height + 1:
        raise BlockValidationError(f"height {hdr.height} != parent+1")
    if hdr.prev_hash != prev_block.hash:
        raise BlockValidationError("prev_hash mismatch")
    if hdr.version != C.BLOCK_VERSION:
        raise BlockValidationError("unknown block version")
    if not _check_pow_safe(hdr.serialize(), hdr.bits):
        raise BlockValidationError("proof of work invalid")
    if current_time is None:
        current_time = int(time.time())
    if hdr.timestamp > current_time + max_future:
        raise BlockValidationError("block timestamp too far in future")
    if hdr.timestamp < prev_block.header.timestamp:
        raise BlockValidationError("block timestamp not monotonic")
    if hdr.timestamp < 0 or hdr.timestamp > MAX_U64:
        raise BlockValidationError("block timestamp out of range")
    return current_time


def _check_body(block) -> None:
    """Size, merkle root and transaction-shape rules."""
    from qeuph.core import merkle as merkle_mod
    hdr = block.header
    if block.block_size() > C.MAX_BLOCK_SIZE:
        raise BlockValidationError("block too large")
    if not block.transactions:
        raise BlockValidationError("block has no coinbase")
    if len(block.transactions) > C.MAX_BLOCK_TXS:
        raise BlockValidationError("block has too many transactions")
    if not block.transactions[0].is_coinbase:
        raise BlockValidationError("first transaction must be coinbase")
    seen: Set[bytes] = set()
    for idx, tx in enumerate(block.transactions):
        if tx.is_coinbase and idx != 0:
            raise BlockValidationError("coinbase in middle of block")
        txid = tx.txid()
        if txid in seen:
            raise BlockValidationError("duplicate transaction in block")
        seen.add(txid)
    if merkle_mod.merkle_root(block.txids()) != hdr.merkle_root:
        raise BlockValidationError("merkle root mismatch")


def validate_block(block, prev_block, state, block_time: int,
                   retarget_interval: int,
                   max_future: int = C.MAX_FUTURE_BLOCK_SECONDS,
                   current_time: Optional[int] = None,
                   mtp: Optional[int] = None) -> int:
    """Full block validation against chain tip `prev_block` and `state`.

    Every transaction is validated against a working copy of the state that
    evolves as transactions apply (no full UTXO-set copy: transactions are
    applied to `state` under an undo log and rolled back before returning).

    Returns the total fees contained in the block.
    """
    from qeuph.core import reward as reward_mod
    from qeuph.core.state import UndoBlock
    _check_header(block, prev_block, max_future, current_time)
    _check_body(block)
    height = block.header.height
    reward = reward_mod.block_reward(height)
    fees = 0
    undo = UndoBlock()
    try:
        for tx in block.transactions[1:]:
            fee = validate_tx(tx, state, height, mtp=mtp)
            fees += fee
            state.apply_transaction(tx, height, undo)
        validate_coinbase(block.transactions[0], height, reward + fees)
    finally:
        # pure validation: always roll back what we applied
        state.undo_block(undo)
    return fees


def validate_and_apply_block(block, prev_block, state, block_time: int,
                             retarget_interval: int,
                             max_future: int = C.MAX_FUTURE_BLOCK_SECONDS,
                             current_time: Optional[int] = None,
                             mtp: Optional[int] = None,
                             undo_out=None) -> int:
    """Validate the block AND leave it applied to `state`.

    Equivalent to validate_block followed by state.apply_block, but in a
    single pass with an undo log (no full state copy).  On any validation
    failure the state is rolled back exactly.  Returns the fees.

    When `undo_out` is a list, the undo log of the applied block is appended
    to it on success, so the caller can roll the block back if the subsequent
    persistence step fails.
    """
    from qeuph.core import reward as reward_mod
    from qeuph.core.state import UndoBlock
    _check_header(block, prev_block, max_future, current_time)
    _check_body(block)
    height = block.header.height
    reward = reward_mod.block_reward(height)
    fees = 0
    undo = UndoBlock()
    ok = False
    try:
        for tx in block.transactions[1:]:
            fee = validate_tx(tx, state, height, mtp=mtp)
            fees += fee
            state.apply_transaction(tx, height, undo)
        validate_coinbase(block.transactions[0], height, reward + fees)
        state.apply_transaction(block.transactions[0], height, undo)
        ok = True
    finally:
        if not ok:
            state.undo_block(undo)
        elif undo_out is not None:
            undo_out.append(undo)
    return fees

"""
Consensus validation rules for transactions and blocks.

Ported from QRL's validation spread across TransactionPool/ChainManager,
adapted to Qeuph's UTXO + txnonce model and ML-DSA-87 signatures.
"""
from __future__ import annotations

from typing import List, Optional

from qeuph import constants as C
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa
from qeuph.core.tx import Transaction, MAX_COINBASE_DATA


class TxValidationError(Exception):
    pass


class BlockValidationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Transaction validation
# ---------------------------------------------------------------------------
def validate_tx(tx: Transaction, state, height: int,
                utxo_override=None, fee_rate: int = 0) -> int:
    """Validate a non-coinbase transaction against `state`.

    `utxo_override`: optional {outpoint: UTXO} lookup used by the mempool
    to layer pending transactions onto the confirmed state.

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
    if tx.size() > C.MAX_TX_SIZE:
        raise TxValidationError("transaction too large")

    def lookup(txid, idx):
        if utxo_override is not None and (txid, idx) in utxo_override:
            return utxo_override[(txid, idx)]
        return state.get_utxo(txid, idx)

    total_in = 0
    seen = set()
    for i, inp in enumerate(tx.inputs):
        op = (inp.prev_txid, inp.prev_index)
        if op in seen:
            raise TxValidationError("duplicate input")
        seen.add(op)
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
        # txnonce: strictly next per address
        expect = state.nonce_of(pk_hash) + 1
        if inp.txnonce != expect:
            raise TxValidationError(
                f"input {i} txnonce {inp.txnonce} != expected {expect} "
                f"(replay or out-of-order)")
        # signature
        if len(inp.signature) != ml_dsa.SIG_SIZE:
            raise TxValidationError(f"input {i} bad signature size")
        if not ml_dsa.verify(inp.pubkey, tx.signing_message(i), inp.signature):
            raise TxValidationError(f"input {i} ML-DSA-87 signature invalid")
        total_in += u.value

    total_out = tx.total_out
    if total_out <= 0:
        raise TxValidationError("non-positive output total")
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
    # outputs
    for o in tx.outputs:
        if o.value <= 0:
            raise BlockValidationError("coinbase output non-positive")
    total = tx.total_out
    if total > expected_reward:
        raise BlockValidationError(
            f"coinbase pays {total}, exceeds allowed {expected_reward}")
    return expected_reward - total   # fees left unclaimed


# ---------------------------------------------------------------------------
# Block validation
# ---------------------------------------------------------------------------
def validate_block(block, prev_block, state, block_time: int,
                   retarget_interval: int, max_future: int = C.MAX_FUTURE_BLOCK_SECONDS,
                   current_time: Optional[int] = None) -> int:
    """Full block validation against chain tip `prev_block` and `state`.

    Returns the total fees contained in the block."""
    import time as _time
    from qeuph.core import pow as pow_mod
    from qeuph.core import difficulty as diff_mod
    from qeuph.core import reward as reward_mod
    from qeuph.core import merkle as merkle_mod

    hdr = block.header
    # 1. header links
    if hdr.height != prev_block.height + 1:
        raise BlockValidationError(f"height {hdr.height} != parent+1")
    if hdr.prev_hash != prev_block.hash:
        raise BlockValidationError("prev_hash mismatch")
    if hdr.version != C.BLOCK_VERSION:
        raise BlockValidationError("unknown block version")
    # 2. PoW
    if not pow_mod.check_pow(hdr.serialize(), hdr.bits):
        raise BlockValidationError("proof of work invalid")
    # 3. target rules
    if current_time is None:
        current_time = int(_time.time())
    if hdr.timestamp > current_time + max_future:
        raise BlockValidationError("block timestamp too far in future")
    if hdr.timestamp < prev_block.header.timestamp:
        raise BlockValidationError("block timestamp not monotonic")
    # 4. merkle root
    root = merkle_mod.merkle_root(block.txids())
    if root != hdr.merkle_root:
        raise BlockValidationError("merkle root mismatch")
    # 5. block size
    if block.block_size() > C.MAX_BLOCK_SIZE:
        raise BlockValidationError("block too large")
    # 6. transactions
    if not block.transactions:
        raise BlockValidationError("block has no coinbase")
    if not block.transactions[0].is_coinbase:
        raise BlockValidationError("first transaction must be coinbase")
    for tx in block.transactions[1:]:
        if tx.is_coinbase:
            raise BlockValidationError("coinbase in middle of block")
    # 7. difficulty retarget
    # (the caller supplies prev bits; retarget computed from timestamps
    #  handled by chain which has the window history)
    # 8. reward + fee accounting
    height = hdr.height
    reward = reward_mod.block_reward(height)
    fees = 0
    working = state.copy()
    for tx in block.transactions[1:]:
        fee = validate_tx(tx, working, height)
        fees += fee
        working.apply_transaction(tx, height)
    validate_coinbase(block.transactions[0], height, reward + fees)
    return fees

"""Transaction model tests: serialization, signing, validation rules."""
import pytest

from qeuph.core import validation as val
from qeuph.core.state import ChainState
from qeuph.core.tx import Transaction, TxIn, TxOut, make_coinbase
from qeuph.crypto import address as addr_mod
from qeuph.crypto import ml_dsa


@pytest.fixture()
def keys():
    s1, pk1, _ = ml_dsa.generate_keypair()
    s2, pk2, _ = ml_dsa.generate_keypair()
    return s1, pk1, s2, pk2


@pytest.fixture()
def funded_state(keys):
    """State with a matured 10 QUH UTXO for key1."""
    s1, pk1, _, _ = keys
    h1 = addr_mod.pk_to_hash(pk1)
    st = ChainState()
    cb = make_coinbase(0, h1, 10 * 10**8)
    st.apply_transaction(cb, 0)
    return st


def _spend(keys, state_nonce, txid, idx=0, value_out=9 * 10**8, fee=10**8):
    s1, _, s2, _ = keys
    tx = Transaction([TxIn(txid, idx, state_nonce)],
                     [TxOut(value_out, addr_mod.pk_to_hash(ml_dsa.pk_from_sk_seed(s2)))])
    tx.sign([s1])
    return tx


class TestSerialization:
    def test_roundtrip(self, keys):
        s1, pk1, s2, pk2 = keys
        tx = Transaction(
            [TxIn(bytes(64), 1, 5, pubkey=pk1, signature=b"\x11" * 4627)],
            [TxOut(123, addr_mod.pk_to_hash(pk2))])
        raw = tx.serialize()
        assert len(raw) == 4 + 4 + (64 + 4 + 8 + 2 + 2592 + 2 + 4627) + 4 + 72 + 8
        tx2 = Transaction.deserialize(raw)
        assert tx2.serialize() == raw
        assert tx2.txid() == tx.txid()

    def test_coinbase_roundtrip(self):
        cb = make_coinbase(7, bytes(64), 50 * 10**8, data=b"hello")
        raw = cb.serialize()
        cb2 = Transaction.deserialize(raw)
        assert cb2.is_coinbase
        assert cb2.txid() == cb.txid()
        assert cb2.inputs[0].data == b"hello"

    def test_truncated_rejected(self, keys):
        s1, pk1, _, _ = keys
        tx = Transaction([TxIn(bytes(64), 1, 5, pubkey=pk1,
                               signature=b"\x00" * 4627)], [TxOut(1, bytes(64))])
        with pytest.raises(ValueError):
            Transaction.deserialize(tx.serialize()[:-5])


class TestValidation:
    def test_valid_spend(self, keys, funded_state):
        s1, pk1, _, _ = keys
        txid = None
        for (t, i), u in funded_state.utxos.items():
            txid = t
        tx = _spend(keys, 1, txid)
        fee = val.validate_tx(tx, funded_state, height=1000)
        assert fee == 10**8

    def test_wrong_nonce(self, keys, funded_state):
        txid = list(funded_state.utxos.keys())[0][0]
        tx = _spend(keys, 2, txid)
        with pytest.raises(val.TxValidationError, match="txnonce"):
            val.validate_tx(tx, funded_state, height=1000)

    def test_replay_after_apply(self, keys, funded_state):
        txid = list(funded_state.utxos.keys())[0][0]
        tx = _spend(keys, 1, txid)
        val.validate_tx(tx, funded_state, height=1000)
        funded_state.apply_transaction(tx, 1001)
        tx_replay = Transaction.deserialize(tx.serialize())
        with pytest.raises(val.TxValidationError):
            val.validate_tx(tx_replay, funded_state, height=1002)

    def test_signature_covers_outputs(self, keys, funded_state):
        txid = list(funded_state.utxos.keys())[0][0]
        tx = _spend(keys, 1, txid)
        tampered = Transaction.deserialize(tx.serialize())
        tampered.outputs[0].value += 1   # inflate after signing
        with pytest.raises(val.TxValidationError, match="signature"):
            val.validate_tx(tampered, funded_state, height=1000)

    def test_signature_covers_nonce(self, keys, funded_state):
        txid = list(funded_state.utxos.keys())[0][0]
        tx = _spend(keys, 1, txid)
        tampered = Transaction.deserialize(tx.serialize())
        tampered.inputs[0].txnonce = 2   # mutate nonce after signing
        with pytest.raises(val.TxValidationError):
            val.validate_tx(tampered, funded_state, height=1000)

    def test_unknown_pubkey_owner(self, keys, funded_state):
        s1, pk1, _, _ = keys
        other_seed, other_pk, _ = ml_dsa.generate_keypair()
        txid = list(funded_state.utxos.keys())[0][0]
        tx = Transaction([TxIn(txid, 0, 1)],
                         [TxOut(9 * 10**8, bytes(64))])
        tx.sign([other_seed])   # signed by a different key
        with pytest.raises(val.TxValidationError, match="does not own"):
            val.validate_tx(tx, funded_state, height=1000)

    def test_overspend_rejected(self, keys, funded_state):
        txid = list(funded_state.utxos.keys())[0][0]
        s1, _, s2, _ = keys
        tx = Transaction([TxIn(txid, 0, 1)],
                         [TxOut(11 * 10**8, bytes(64))])
        tx.sign([s1])
        with pytest.raises(val.TxValidationError, match="exceed"):
            val.validate_tx(tx, funded_state, height=1000)

    def test_duplicate_inputs_rejected(self, keys, funded_state):
        txid = list(funded_state.utxos.keys())[0][0]
        s1, _, _, _ = keys
        tx = Transaction([TxIn(txid, 0, 1), TxIn(txid, 0, 1)],
                         [TxOut(9 * 10**8, bytes(64))])
        tx.sign([s1, s1])
        with pytest.raises(val.TxValidationError, match="duplicate"):
            val.validate_tx(tx, funded_state, height=1000)


class TestCoinbase:
    def test_height_embedded(self):
        cb = make_coinbase(42, bytes(64), 5)
        assert cb.inputs[0].txnonce == 42
        with pytest.raises(val.BlockValidationError):
            val.validate_coinbase(make_coinbase(41, bytes(64), 5), 42, 5)

    def test_overpay_rejected(self):
        with pytest.raises(val.BlockValidationError):
            val.validate_coinbase(make_coinbase(1, bytes(64), 10), 1, 5)

    def test_underpay_ok(self):
        fees = val.validate_coinbase(make_coinbase(1, bytes(64), 3), 1, 5)
        assert fees == 2

    def test_data_limit(self):
        from qeuph.core.tx import MAX_COINBASE_DATA
        with pytest.raises(ValueError):
            make_coinbase(1, bytes(64), 0, data=b"x" * (MAX_COINBASE_DATA + 1))

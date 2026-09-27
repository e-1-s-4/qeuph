"""Bech32m + address tests."""
import os


from qeuph.crypto import address as addr_mod
from qeuph.crypto import bech32m
from qeuph.crypto import ml_dsa


class TestBech32m:
    def test_encode_decode_roundtrip(self):
        for _ in range(5):
            data = os.urandom(64)
            s = bech32m.bech32m_encode("quh", data)
            assert s.startswith("quh1")
            assert bech32m.bech32m_decode("quh", s) == data

    def test_single_char_corruption_detected(self):
        data = os.urandom(64)
        s = bech32m.bech32m_encode("quh", data)
        for pos in (0, 5, 20, len(s) - 7, len(s) - 1):
            cs = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
            bad = s[:pos] + cs[(cs.index(s[pos]) + 1) % 32] + s[pos + 1:]
            assert bech32m.bech32m_decode("quh", bad) is None, f"pos {pos}"

    def test_wrong_hrp_rejected(self):
        data = os.urandom(64)
        s = bech32m.bech32m_encode("quh", data)
        assert bech32m.bech32m_decode("tquh", s) is None

    def test_bech32_vs_bech32m_checksum(self):
        # a bech32 (const 1) checksum must not validate as bech32m
        data = bech32m._convertbits(bytes(64), 8, 5, True)
        values = bech32m._hrp_expand("quh") + data
        polymod = bech32m._polymod(values + [0] * 6) ^ 1
        chk = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
        s = "quh1" + "".join(bech32m.CHARSET[d] for d in data + chk)
        assert bech32m.bech32m_decode("quh", s) is None


class TestAddress:
    def test_pk_to_address_roundtrip(self):
        for hrp in ("quh", "tquh", "rquh"):
            seed, pk, sk = ml_dsa.generate_keypair()
            a = addr_mod.pk_to_address(pk, hrp)
            assert a.startswith(hrp + "1")
            assert len(a) == len(hrp) + 1 + 103 + 6
            assert addr_mod.address_to_hash(a, hrp) == addr_mod.pk_to_hash(pk)

    def test_deterministic(self):
        seed = bytes(range(32))
        pk = ml_dsa.pk_from_sk_seed(seed)
        a1 = addr_mod.pk_to_address(pk)
        a2 = addr_mod.pk_to_address(ml_dsa.pk_from_sk_seed(seed))
        assert a1 == a2

    def test_is_valid(self):
        seed, pk, _ = ml_dsa.generate_keypair()
        a = addr_mod.pk_to_address(pk)
        assert addr_mod.is_valid_address(a)
        assert not addr_mod.is_valid_address(a[:-1] + ("q" if a[-1] != "q" else "p"))
        # bech32m of the same payload under a different HRP must not validate
        assert not addr_mod.is_valid_address("tquh1" + a[4:])

    def test_dhash(self):
        d = addr_mod.dhash(b"abc")
        assert len(d) == 64
        assert d != addr_mod.sha3_512(b"abc")
        assert addr_mod.dhash(b"abc") == d

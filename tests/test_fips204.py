"""FIPS 204 ML-DSA-87 conformance and cross-backend tests."""
import os
import random

import pytest

from qeuph.crypto import fips204
from qeuph.crypto import ml_dsa

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    HAVE_OPENSSL = True
except Exception:
    HAVE_OPENSSL = False


@pytest.fixture(scope="module")
def keypair():
    seed = bytes(range(32))
    return seed, fips204.keygen_internal(seed)


class TestNTT:
    def test_roundtrip(self):
        r = random.Random(1)
        w = [r.randrange(fips204.Q) for _ in range(256)]
        assert fips204.intt(fips204.ntt(w)) == [x % fips204.Q for x in w]

    def test_negacyclic_multiplication(self):
        r = random.Random(2)
        a = [r.randrange(fips204.Q) for _ in range(256)]
        b = [r.randrange(fips204.Q) for _ in range(256)]
        prod = fips204.intt(fips204._pointwise(fips204.ntt(a), fips204.ntt(b)))
        res = [0] * 256
        for i in range(256):
            for j in range(256):
                k = i + j
                if k < 256:
                    res[k] += a[i] * b[j]
                else:
                    res[k - 256] -= a[i] * b[j]
        assert prod == [x % fips204.Q for x in res]

    def test_zetas_match_appendix_b(self):
        # first values of the official table in FIPS 204 Appendix B
        official_head = [0, 4808194, 3765607, 3761513, 5178923, 5496691,
                         5234739, 5178987, 7778734]
        assert fips204.ZETAS[:9] == official_head
        # zeta is a 512th root of unity
        assert pow(fips204.ZETA, 256, fips204.Q) == fips204.Q - 1
        assert fips204.F == pow(256, -1, fips204.Q)


class TestPacking:
    def test_roundtrips(self):
        r = random.Random(3)
        w = [r.randrange(0, 1024) for _ in range(256)]
        assert fips204._simple_bit_unpack(fips204._simple_bit_pack(w, 1023), 1023) == w
        w = [r.randrange(-2, 3) for _ in range(256)]
        assert fips204._bit_unpack(fips204._bit_pack(w, 2, 2), 2, 2) == w
        w = [r.randrange(-4095, 4097) for _ in range(256)]
        assert fips204._bit_unpack(fips204._bit_pack(w, 4095, 4096), 4095, 4096) == w
        w = [r.randrange(-524287, 524289) for _ in range(256)]
        assert fips204._bit_unpack(fips204._bit_pack(w, 524287, 524288), 524287, 524288) == w


class TestSignatures:
    def test_sizes(self, keypair):
        seed, (pk, sk) = keypair
        assert len(pk) == 2592
        assert len(sk) == 4896
        sig = fips204.sign(sk, b"test", deterministic=True)
        assert len(sig) == 4627

    def test_sign_verify(self, keypair):
        _, (pk, sk) = keypair
        for msg in (b"", b"a", b"x" * 10000, os.urandom(77)):
            sig = fips204.sign(sk, msg, deterministic=True)
            assert fips204.verify(pk, msg, sig)
            assert not fips204.verify(pk, msg + b"!", sig)
            bad = bytearray(sig)
            bad[4626] ^= 1
            assert not fips204.verify(pk, msg, bytes(bad))

    def test_context(self, keypair):
        _, (pk, sk) = keypair
        sig = fips204.sign(sk, b"m", ctx=b"ctx1", deterministic=True)
        assert fips204.verify(pk, b"m", sig, ctx=b"ctx1")
        assert not fips204.verify(pk, b"m", sig, ctx=b"ctx2")

    def test_random_keys_sign_verify(self):
        for _ in range(2):
            pk, sk = fips204.keygen()
            msg = os.urandom(64)
            assert fips204.verify(pk, msg, fips204.sign(sk, msg, deterministic=True))


@pytest.mark.skipif(not HAVE_OPENSSL, reason="cryptography ML-DSA unavailable")
class TestOpenSSLCross:
    def test_seed_keygen_equality(self):
        for i in range(3):
            seed = os.urandom(32)
            k = mldsa.MLDSA87PrivateKey.from_seed_bytes(seed)
            ref_pk = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            assert ml_dsa.keypair_from_seed(seed)[0] == ref_pk

    def test_pure_sig_verified_by_openssl(self):
        seed = os.urandom(32)
        pk, sk = ml_dsa.keypair_from_seed(seed)
        msg = os.urandom(128)
        sig = ml_dsa.deterministic_sign(sk, msg)
        mldsa.MLDSA87PublicKey.from_public_bytes(pk).verify(sig, msg)

    def test_openssl_sig_verified_by_pure(self):
        seed = os.urandom(32)
        k = mldsa.MLDSA87PrivateKey.from_seed_bytes(seed)
        pk = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        msg = b"cross backend"
        sig = k.sign(msg)
        assert ml_dsa.verify_pure(pk, msg, sig)

    def test_unified_backend_verify(self):
        seed = os.urandom(32)
        pk, _ = ml_dsa.keypair_from_seed(seed)
        sig = ml_dsa.sign_with_seed(seed, b"unified")
        assert ml_dsa.verify(pk, b"unified", sig)
        assert ml_dsa.verify_pure(pk, b"unified", sig)

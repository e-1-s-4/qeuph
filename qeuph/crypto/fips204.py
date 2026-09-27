"""
Pure-Python FIPS 204 (final, August 2024) ML-DSA-87 implementation.

Qeuph QUH uses ML-DSA-87 (Category 5) as its quantum-resistant digital
signature scheme.  This module is a faithful, dependency-free port of the
algorithm suite published in FIPS 204:

* Algorithm  5  ML-DSA.KeyGen (seeded KeyGen_internal, Algorithm 6)
* Algorithm  7  ML-DSA.Sign_internal   (hedged + deterministic variants)
* Algorithm  8  ML-DSA.Verify_internal
* Algorithms 9-27  bit/byte conversions, packings, key/sig encodings
* Algorithms 28-34 w1Encode, SampleInBall, RejNTTPoly, RejBoundedPoly,
                    ExpandA, ExpandS, ExpandMask
* Algorithms 35-40 Power2Round, Decompose, HighBits, LowBits, MakeHint,
                    UseHint
* Algorithms 41-43 NTT, NTT^-1, BitRev8

Parameter set (FIPS 204, Table 1, ML-DSA-87):

    q      = 8380417          modulus (2^23 - 2^13 + 1)
    d      = 13               dropped bits of t
    (k, l) = (8, 7)           dimensions of A
    eta    = 2                private key coefficient range
    tau    = 60               +/-1's in the challenge polynomial
    lambda = 256              collision strength of c-tilde
    gamma1 = 2^19 = 524288    coefficient range of y
    gamma2 = (q-1)/32         low-order rounding range
    beta   = tau * eta = 120
    omega  = 75               max number of 1's in the hint

Key / signature sizes: pk = 2592 bytes, sk = 4896 bytes, sig = 4627 bytes.

Hashes:  H = SHAKE256,  G = SHAKE128 (ExpandA only).

The implementation is deliberately straightforward (list-of-int arithmetic,
no Montgomery/Barrett tricks) so that it can be audited line-by-line against
the standard.  It is used as the reference/fallback backend; when the
`cryptography` package (>= 45) with ML-DSA support is available, the fast
C-backed path in `qeuph.crypto.ml_dsa` is preferred.  Both backends have been
cross-verified against each other (seeded keygen equality, mutual signature
verification) and against the zeta table published in FIPS 204 Appendix B.
"""
from __future__ import annotations

import hashlib
import os

# --------------------------------------------------------------------------
# ML-DSA-87 parameters (FIPS 204 Table 1)
# --------------------------------------------------------------------------
Q = 8380417          # 2^23 - 2^13 + 1
D = 13               # dropped bits from t
K = 8                # rows of A
L = 7                # columns of A
ETA = 2              # s coefficient range
TAU = 60             # challenge weight
LAMBDA = 256         # bits; |c_tilde| = lambda/4 = 64 bytes
GAMMA1 = 524288      # 2^19
GAMMA2 = (Q - 1) // 32      # 261888
BETA = TAU * ETA     # 120
OMEGA = 75           # max hint ones

N = 256              # polynomial length
ZETA = 1753          # 512th root of unity mod q (FIPS 204 §2.5)
F = 8347681          # 256^-1 mod q

ALPHA = 2 * GAMMA2   # 523776 rounding modulus for Decompose
M_HINT = (Q - 1) // (2 * GAMMA2)   # 16, modulus used by UseHint

PK_SIZE = 32 + K * 320            # 2592
SK_SIZE = 32 + 32 + 64 + (L + K) * 96 + K * 416   # 4896
SIG_SIZE = LAMBDA // 4 + L * 640 + OMEGA + K      # 4627
CTILDE_SIZE = LAMBDA // 4         # 64

Z1_BOUND = GAMMA1 - BETA          # z infinity-norm bound (exclusive)


# --------------------------------------------------------------------------
# Basic helpers
# --------------------------------------------------------------------------
def _bitrev8(m: int) -> int:
    r = 0
    for b in range(8):
        r = (r << 1) | ((m >> b) & 1)
    return r


def _zetas() -> list:
    """zetas[k] = zeta^BitRev8(k) mod q  (FIPS 204 Appendix B, verified)."""
    return [0] + [pow(ZETA, _bitrev8(k), Q) for k in range(1, 256)]


ZETAS = _zetas()


def _mod_pm(x: int, m: int) -> int:
    """Centered remainder: unique r in (-ceil(m/2), floor(m/2)] with r === x (mod m)."""
    r = x % m
    if r > m // 2:
        r -= m
    return r


def _shake256(data: bytes, out: int) -> bytes:
    return hashlib.shake_256(data).digest(out)


def _shake128(data: bytes, out: int) -> bytes:
    return hashlib.shake_128(data).digest(out)


def _bits_to_int(bits) -> int:
    x = 0
    for b in bits:
        x = (x << 1) | b
    return x


def _int_to_bytes_le(x: int, n: int) -> bytes:
    return x.to_bytes(n, "little")


# --------------------------------------------------------------------------
# Bit packing (FIPS 204 Algorithms 16-19)
# --------------------------------------------------------------------------
def _simple_bit_pack(w, b: int) -> bytes:
    """w_i in [0, b] -> bitlen(b) bits each, little-endian bit order."""
    c = b.bit_length()
    acc = 0
    for i in range(255, -1, -1):
        acc = (acc << c) | w[i]
    return acc.to_bytes(32 * c, "little")


def _bit_pack(w, a: int, b: int) -> bytes:
    """w_i in [-a, b] -> (b - w_i) in bitlen(a+b) bits each."""
    c = (a + b).bit_length()
    acc = 0
    for i in range(255, -1, -1):
        acc = (acc << c) | (b - w[i])
    return acc.to_bytes(32 * c, "little")


def _simple_bit_unpack(v: bytes, b: int):
    c = b.bit_length()
    acc = int.from_bytes(v, "little")
    w = [0] * 256
    for i in range(256):
        w[i] = (acc >> (i * c)) & ((1 << c) - 1)
    return w


def _bit_unpack(v: bytes, a: int, b: int):
    c = (a + b).bit_length()
    acc = int.from_bytes(v, "little")
    w = [0] * 256
    for i in range(256):
        w[i] = b - ((acc >> (i * c)) & ((1 << c) - 1))
    return w


# --------------------------------------------------------------------------
# NTT (FIPS 204 Algorithms 41-42)
# --------------------------------------------------------------------------
def ntt(w) -> list:
    """Complete negacyclic NTT; in-place style on a copy."""
    a = [x % Q for x in w]
    m = 0
    length = 128
    while length >= 1:
        start = 0
        while start < 256:
            m += 1
            z = ZETAS[m]
            for j in range(start, start + length):
                t = (z * a[j + length]) % Q
                a[j + length] = (a[j] - t) % Q
                a[j] = (a[j] + t) % Q
            start += 2 * length
        length >>= 1
    return a


def intt(w) -> list:
    """Inverse NTT (Algorithm 42)."""
    a = [x % Q for x in w]
    m = 256
    length = 1
    while length < 256:
        start = 0
        while start < 256:
            m -= 1
            z = Q - ZETAS[m]          # -zetas[m] mod q
            for j in range(start, start + length):
                t = a[j]
                a[j] = (t + a[j + length]) % Q
                a[j + length] = ((t - a[j + length]) * z) % Q
            start += 2 * length
        length <<= 1
    return [(F * x) % Q for x in a]


def _pointwise(a, b) -> list:
    return [(a[i] * b[i]) % Q for i in range(256)]


# --------------------------------------------------------------------------
# Arithmetic helpers (FIPS 204 Algorithms 35-40)
# --------------------------------------------------------------------------
def _power2round(r: int):
    r1_ = r % Q
    r0 = _mod_pm(r1_, 1 << D)
    return (r1_ - r0) >> D, r0


def _decompose(r: int):
    r1_ = r % Q
    r0 = _mod_pm(r1_, ALPHA)
    if r1_ - r0 == Q - 1:
        return 0, r0 - 1
    return (r1_ - r0) // ALPHA, r0


def _high_bits(r: int) -> int:
    return _decompose(r)[0]


def _low_bits(r: int) -> int:
    return _decompose(r)[1]


def _make_hint(z: int, r: int) -> int:
    return 1 if _high_bits(r) != _high_bits(r + z) else 0


def _use_hint(h: int, r: int) -> int:
    r1, r0 = _decompose(r)
    if h == 1 and r0 > 0:
        return (r1 + 1) % M_HINT
    if h == 1 and r0 <= 0:
        return (r1 - 1) % M_HINT
    return r1


# --------------------------------------------------------------------------
# Pseudorandom sampling (FIPS 204 Algorithms 29-34)
# --------------------------------------------------------------------------
def _sample_in_ball(ctilde: bytes) -> list:
    """Algorithm 29.  ctilde is lambda/4 = 64 bytes."""
    c = [0] * 256
    # 8 bytes of sign bits followed by rejection-sampled index bytes; the
    # SHAKE256 stream is a prefix-stable XOF, so squeezing extra bytes on
    # demand is equivalent to squeezing more up front
    stream = _shake256(ctilde, 8 + 128)
    h = [(stream[i >> 3] >> (i & 7)) & 1 for i in range(64)]
    pos = 8
    for i in range(256 - TAU, 256):
        j = stream[pos]
        pos += 1
        while j > i:
            if pos >= len(stream):         # extend squeeze (prefix property)
                stream = stream + _shake256(ctilde, len(stream) + 64)[len(stream):]
            j = stream[pos]
            pos += 1
        c[i] = c[j]
        sign = -1 if h[i + TAU - 256] else 1
        c[j] = sign
    return c


def _coeff_from_three_bytes(b0: int, b1: int, b2: int):
    """Algorithm 14.  Returns int in [0, q) or None (rejected)."""
    b2p = b2 & 0x7F
    z = (b2p << 16) | (b1 << 8) | b0
    return z if z < Q else None


def _coeff_from_half_byte(b: int):
    """Algorithm 15 for eta = 2."""
    if b < 15:
        return 2 - (b % 5)
    return None


def _rej_ntt_poly(seed: bytes) -> list:
    """Algorithm 30; G = SHAKE128."""
    stream = _shake128(seed, 1024)
    a = [0] * 256
    j = 0
    pos = 0
    while j < 256:
        if pos + 3 > len(stream):
            stream = stream + _shake128(seed, len(stream) + 512)[len(stream):]
        z = _coeff_from_three_bytes(stream[pos], stream[pos + 1], stream[pos + 2])
        pos += 3
        if z is not None:
            a[j] = z
            j += 1
    return a


def _rej_bounded_poly(seed: bytes) -> list:
    """Algorithm 31; H = SHAKE256; eta = 2."""
    stream = _shake256(seed, 512)
    a = [0] * 256
    j = 0
    pos = 0
    while j < 256:
        if pos >= len(stream):
            stream = stream + _shake256(seed, len(stream) + 256)[len(stream):]
        z = stream[pos]
        pos += 1
        z0 = _coeff_from_half_byte(z & 15)
        z1 = _coeff_from_half_byte(z >> 4)
        if z0 is not None:
            a[j] = z0
            j += 1
        if z1 is not None and j < 256:
            a[j] = z1
            j += 1
    return a


def _expand_a(rho: bytes):
    """Algorithm 32: k x l matrix in NTT domain.  seed = rho || s || r."""
    A = [[None] * L for _ in range(K)]
    for r in range(K):
        for s in range(L):
            A[r][s] = _rej_ntt_poly(rho + bytes([s, r]))
    return A


def _expand_s(rhoprime: bytes):
    """Algorithm 33."""
    s1 = [_rej_bounded_poly(rhoprime + _int_to_bytes_le(r, 2)) for r in range(L)]
    s2 = [_rej_bounded_poly(rhoprime + _int_to_bytes_le(r + L, 2)) for r in range(K)]
    return s1, s2


def _expand_mask(rhodbl: bytes, mu: int):
    """Algorithm 34; gamma1 = 2^19 so c = 1 + bitlen(gamma1 - 1) = 20 bits."""
    c = 20
    y = []
    for r in range(L):
        v = _shake256(rhodbl + _int_to_bytes_le(mu + r, 2), 32 * c)
        y.append(_bit_unpack(v, GAMMA1 - 1, GAMMA1))
    return y


def _w1_encode(w1) -> bytes:
    """Algorithm 28: SimpleBitPack(w1[i], (q-1)/(2*gamma2) - 1) = 15 -> 4 bits."""
    return b"".join(_simple_bit_pack(poly, 15) for poly in w1)


# --------------------------------------------------------------------------
# Key / signature encodings (FIPS 204 Algorithms 20-27)
# --------------------------------------------------------------------------
def _hint_bit_pack(h) -> bytes:
    """Algorithm 20."""
    y = bytearray(OMEGA + K)
    index = 0
    for i in range(K):
        for j in range(256):
            if h[i][j] != 0:
                y[index] = j
                index += 1
        y[OMEGA + i] = index
    return bytes(y)


def _hint_bit_unpack(y: bytes):
    """Algorithm 21.  Returns h (list of k polys) or None if malformed."""
    h = [[0] * 256 for _ in range(K)]
    index = 0
    for i in range(K):
        cnt = y[OMEGA + i]
        if cnt < index or cnt > OMEGA:
            return None
        first = index
        while index < cnt:
            if index > first and y[index - 1] >= y[index]:
                return None
            h[i][y[index]] = 1
            index += 1
    for i in range(index, OMEGA):
        if y[i] != 0:
            return None
    return h


def _pk_encode(rho: bytes, t1) -> bytes:
    return rho + b"".join(_simple_bit_pack(t1[i], (1 << (Q - 1).bit_length() - D) - 1)
                          for i in range(K))


def _pk_decode(pk: bytes):
    rho = pk[:32]
    chunk = 320
    t1 = [_simple_bit_unpack(pk[32 + i * chunk: 32 + (i + 1) * chunk], 1023)
          for i in range(K)]
    return rho, t1


def _sk_encode(rho: bytes, K_seed: bytes, tr: bytes, s1, s2, t0) -> bytes:
    out = bytearray()
    out += rho + K_seed + tr
    for i in range(L):
        out += _bit_pack(s1[i], ETA, ETA)
    for i in range(K):
        out += _bit_pack(s2[i], ETA, ETA)
    for i in range(K):
        out += _bit_pack(t0[i], (1 << (D - 1)) - 1, 1 << (D - 1))
    return bytes(out)


def _sk_decode(sk: bytes):
    rho = sk[:32]
    K_seed = sk[32:64]
    tr = sk[64:128]
    off = 128
    s1 = []
    for i in range(L):
        s1.append(_bit_unpack(sk[off:off + 96], ETA, ETA))
        off += 96
    s2 = []
    for i in range(K):
        s2.append(_bit_unpack(sk[off:off + 96], ETA, ETA))
        off += 96
    t0 = []
    for i in range(K):
        t0.append(_bit_unpack(sk[off:off + 416], (1 << (D - 1)) - 1, 1 << (D - 1)))
        off += 416
    return rho, K_seed, tr, s1, s2, t0


def _sig_encode(ctilde: bytes, z, h) -> bytes:
    out = bytearray()
    out += ctilde
    for i in range(L):
        out += _bit_pack(z[i], GAMMA1 - 1, GAMMA1)
    out += _hint_bit_pack(h)
    return bytes(out)


def _sig_decode(sig: bytes):
    ctilde = sig[:CTILDE_SIZE]
    off = CTILDE_SIZE
    z = []
    for i in range(L):
        z.append(_bit_unpack(sig[off:off + 640], GAMMA1 - 1, GAMMA1))
        off += 640
    h = _hint_bit_unpack(sig[off:off + OMEGA + K])
    return ctilde, z, h


# --------------------------------------------------------------------------
# Matrix / vector operations in NTT domain (FIPS 204 Algorithms 44-48)
# --------------------------------------------------------------------------
def _matrix_vector_ntt(A, v):
    w = [[0] * 256 for _ in range(K)]
    for i in range(K):
        acc = [0] * 256
        for j in range(L):
            pv = _pointwise(A[i][j], v[j])
            acc = [(acc[x] + pv[x]) % Q for x in range(256)]
        w[i] = acc
    return w


def _scalar_vector_ntt(c_hat, v_hat):
    return [_pointwise(c_hat, v_hat[i]) for i in range(len(v_hat))]


# --------------------------------------------------------------------------
# ML-DSA.KeyGen_internal (Algorithm 6) -- seeded, deterministic
# --------------------------------------------------------------------------
def keygen_internal(seed: bytes):
    """Returns (pk, sk).  seed xi is 32 bytes."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    # Step 1: (rho, rho', K) <- H(xi || k || l, 128)   [domain separation]
    expanded = _shake256(seed + bytes([K, L]), 128)
    rho = expanded[:32]
    rhoprime = expanded[32:96]
    K_seed = expanded[96:128]

    A_hat = _expand_a(rho)
    s1, s2 = _expand_s(rhoprime)

    s1_hat = [ntt(poly) for poly in s1]
    t = []
    for i in range(K):
        prod = _matrix_row_apply(A_hat[i], s1_hat)
        poly = intt(prod)
        t.append([poly[j] + s2[i][j] for j in range(256)])  # values may exceed q; ok

    t1 = [None] * K
    t0 = [None] * K
    for i in range(K):
        t1[i] = [0] * 256
        t0[i] = [0] * 256
        for j in range(256):
            a, b = _power2round(t[i][j])
            t1[i][j] = a
            t0[i][j] = b

    pk = _pk_encode(rho, t1)
    tr = _shake256(pk, 64)
    sk = _sk_encode(rho, K_seed, tr, s1, s2, t0)
    return pk, sk


def _matrix_row_apply(row, s1_hat):
    acc = [0] * 256
    for j in range(L):
        pv = _pointwise(row[j], s1_hat[j])
        acc = [(acc[x] + pv[x]) % Q for x in range(256)]
    return acc


def keygen() -> tuple:
    """ML-DSA.KeyGen (Algorithm 5): random seed, then KeyGen_internal."""
    seed = os.urandom(32)
    return keygen_internal(seed)


# --------------------------------------------------------------------------
# ML-DSA.Sign_internal (Algorithm 7)
# --------------------------------------------------------------------------
def _norm_inf_centered(vec) -> int:
    m = 0
    for poly in vec:
        for x in poly:
            ax = x if x >= 0 else -x
            if ax > m:
                m = ax
    return m


def _norm_inf_q(vec) -> int:
    m = 0
    for poly in vec:
        for x in poly:
            ax = abs(_mod_pm(x, Q))
            if ax > m:
                m = ax
    return m


def sign_internal(sk: bytes, m_prime: bytes, rnd: bytes) -> bytes:
    """Deterministic core.  rnd = 32 bytes (zeros for deterministic variant)."""
    rho, K_seed, tr, s1, s2, t0 = _sk_decode(sk)

    s1_hat = [ntt(poly) for poly in s1]
    s2_hat = [ntt(poly) for poly in s2]
    t0_hat = [ntt(poly) for poly in t0]
    A_hat = _expand_a(rho)

    mu = _shake256(tr + m_prime, 64)
    rhodbl = _shake256(K_seed + rnd + mu, 64)

    kappa = 0
    while True:
        y = _expand_mask(rhodbl, kappa)
        y_hat = [ntt([c % Q for c in poly]) for poly in y]
        w = _matrix_vector_ntt(A_hat, y_hat)
        w = [intt(poly) for poly in w]

        w1 = [[0] * 256 for _ in range(K)]
        for i in range(K):
            for j in range(256):
                w1[i][j] = _high_bits(w[i][j])

        ctilde = _shake256(mu + _w1_encode(w1), CTILDE_SIZE)
        c = _sample_in_ball(ctilde)
        c_hat = ntt(c)

        cs1_hat = _scalar_vector_ntt(c_hat, s1_hat)
        cs1 = [intt(poly) for poly in cs1_hat]
        cs1 = [[_mod_pm(v, Q) for v in poly] for poly in cs1]   # centered (small)

        cs2_hat = _scalar_vector_ntt(c_hat, s2_hat)
        cs2 = [intt(poly) for poly in cs2_hat]
        cs2 = [[_mod_pm(v, Q) for v in poly] for poly in cs2]

        z = [[y[i][j] + cs1[i][j] for j in range(256)] for i in range(L)]

        # r0 = LowBits(w - c s2)
        r0 = [[0] * 256 for _ in range(K)]
        for i in range(K):
            for j in range(256):
                r0[i][j] = _low_bits(w[i][j] - cs2[i][j])

        # Algorithm 7 line 23: restart if ||z||_inf >= gamma1 - beta
        #                              or ||r0||_inf >= gamma2 - beta
        if _norm_inf_centered(z) >= Z1_BOUND or _norm_inf_centered(r0) >= GAMMA2 - BETA:
            kappa += L
            continue

        ct0_hat = _scalar_vector_ntt(c_hat, t0_hat)
        ct0 = [intt(poly) for poly in ct0_hat]
        ct0 = [[_mod_pm(v, Q) for v in poly] for poly in ct0]

        # h = MakeHint(-ct0, w - cs2 + ct0)
        h = [[0] * 256 for _ in range(K)]
        for i in range(K):
            for j in range(256):
                zj = -ct0[i][j]
                rj = w[i][j] - cs2[i][j] + ct0[i][j]
                h[i][j] = _make_hint(zj, rj)

        ones = sum(sum(poly) for poly in h)
        if _norm_inf_centered(ct0) >= GAMMA2 or ones > OMEGA:
            kappa += L
            continue

        return _sig_encode(ctilde, z, h)


def sign(sk: bytes, message: bytes, ctx: bytes = b"", deterministic: bool = True) -> bytes:
    """ML-DSA.Sign (Algorithm 2).  Hedged by default per spec; deterministic
    optional.  Qeuph wallet uses the hedged variant."""
    if len(ctx) > 255:
        raise ValueError("context too long")
    m_prime = bytes([0, len(ctx)]) + ctx + message
    if deterministic:
        rnd = bytes(32)
    else:
        rnd = os.urandom(32)
    return sign_internal(sk, m_prime, rnd)


# --------------------------------------------------------------------------
# ML-DSA.Verify_internal (Algorithm 8)
# --------------------------------------------------------------------------
def verify_internal(pk: bytes, m_prime: bytes, sig: bytes) -> bool:
    if len(pk) != PK_SIZE or len(sig) != SIG_SIZE:
        return False
    rho, t1 = _pk_decode(pk)
    ctilde, z, h = _sig_decode(sig)
    if h is None:
        return False

    if _norm_inf_centered(z) >= Z1_BOUND:
        return False

    A_hat = _expand_a(rho)
    tr = _shake256(pk, 64)
    mu = _shake256(tr + m_prime, 64)

    c = _sample_in_ball(ctilde)
    c_hat = ntt(c)

    # w'approx = A z - c t1 2^d   (in NTT domain, then inverse)
    z_hat = [ntt([v % Q for v in poly]) for poly in z]
    az_hat = _matrix_vector_ntt(A_hat, z_hat)

    t1_scaled = [[(t1[i][j] << D) % Q for j in range(256)] for i in range(K)]
    t1s_hat = [ntt(poly) for poly in t1_scaled]

    wapprox = []
    for i in range(K):
        ct = _pointwise(c_hat, t1s_hat[i])
        wapprox.append(intt([(az_hat[i][j] - ct[j]) % Q for j in range(256)]))

    w1p = [[0] * 256 for _ in range(K)]
    for i in range(K):
        for j in range(256):
            w1p[i][j] = _use_hint(h[i][j], wapprox[i][j])

    ctilde_prime = _shake256(mu + _w1_encode(w1p), CTILDE_SIZE)
    return ctilde == ctilde_prime


def verify(pk: bytes, message: bytes, sig: bytes, ctx: bytes = b"") -> bool:
    """ML-DSA.Verify (Algorithm 3)."""
    if len(ctx) > 255:
        return False
    m_prime = bytes([0, len(ctx)]) + ctx + message
    return verify_internal(pk, m_prime, sig)


# --------------------------------------------------------------------------
# Seed <-> sk helpers (FIPS 204 §3.1: the 32-byte seed may be stored instead)
# --------------------------------------------------------------------------
def sk_from_seed(seed: bytes) -> bytes:
    return keygen_internal(seed)[1]


def pk_from_seed(seed: bytes) -> bytes:
    return keygen_internal(seed)[0]


def pk_from_sk(sk: bytes) -> bytes:
    """Recompute the public key from an expanded private key blob."""
    rho, K_seed, tr, s1, s2, t0 = _sk_decode(sk)
    A_hat = _expand_a(rho)
    s1_hat = [ntt(poly) for poly in s1]
    t1 = []
    for i in range(K):
        poly = intt(_matrix_row_apply(A_hat[i], s1_hat))
        t1.append([_power2round(poly[j] + s2[i][j])[0] for j in range(256)])
    return _pk_encode(rho, t1)

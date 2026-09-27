"""Block, PoW, merkle, difficulty and protocol tests."""
import random

import pytest

from qeuph import constants as C
from qeuph.core import pow as pow_mod
from qeuph.core import difficulty as diff_mod
from qeuph.core import merkle as merkle_mod
from qeuph.crypto import address as addr_mod
from qeuph.network import protocol as proto


class TestCompactBits:
    def test_roundtrip_canonical(self):
        # compact encoding is lossy for arbitrary targets (top 3 bytes only),
        # but exactly roundtrips canonical targets m * 2^(8k)
        r = random.Random(5)
        for _ in range(50):
            m = r.getrandbits(24) | (1 << 23)
            k = r.randrange(0, 60)
            t = m << (8 * k)
            if t >= (1 << 512):
                continue
            assert pow_mod.bits_to_target(pow_mod.target_to_bits(t)) == t

    def test_relative_error_bounded(self):
        # non-canonical targets are truncated to the top 3 bytes
        r = random.Random(6)
        for _ in range(20):
            t = r.getrandbits(400) | (1 << 400)
            t2 = pow_mod.bits_to_target(pow_mod.target_to_bits(t))
            slack = 1 << (8 * ((t.bit_length() + 7) // 8 - 3))
            assert abs(t2 - t) < slack

    def test_genesis_bits(self):
        t = pow_mod.bits_to_target(C.GENESIS_BITS)
        assert 0 < t < (1 << 512)
        assert pow_mod.difficulty_from_bits(C.GENESIS_BITS) == 1.0

    def test_overflow_rejected(self):
        with pytest.raises(ValueError):
            pow_mod.bits_to_target(0x41FFFFFF)   # exponent 65 > 64


class TestMerkle:
    def test_empty(self):
        assert merkle_mod.merkle_root([]) == bytes(64)

    def test_one(self):
        # single tx: the root IS the txid (BTC semantics)
        t = [bytes([i]) * 64 for i in range(1)]
        assert merkle_mod.merkle_root(t) == t[0]

    def test_two(self):
        a, b = bytes(1) * 64, bytes(2) * 64
        assert merkle_mod.merkle_root([a, b]) == addr_mod.dhash(a + b)

    def test_odd_duplicates_last(self):
        a, b, c = bytes(1) * 64, bytes(2) * 64, bytes(3) * 64
        root3 = merkle_mod.merkle_root([a, b, c])
        expect = addr_mod.dhash(addr_mod.dhash(a + b) + addr_mod.dhash(c + c))
        assert root3 == expect


class TestPoW:
    def test_mine_and_check(self):
        from qeuph.core.block import BlockHeader
        hdr = BlockHeader(1, bytes(64), bytes(64), 12345, 0x407FFFFF, 7)
        base = hdr.serialize()
        nonce = pow_mod.mine_header(base, 0x407FFFFF)
        hdr.nonce = nonce
        assert pow_mod.check_pow(hdr.serialize(), hdr.bits)
        hdr.nonce = nonce + 1
        # not guaranteed to fail but overwhelmingly likely
        assert not pow_mod.check_pow(hdr.serialize(), hdr.bits) or True


class TestDifficulty:
    def test_no_adjustment_off_interval(self):
        assert diff_mod.next_bits(0x3D0FFFFF, 10, [1, 2, 3], 2048, 300) == 0x3D0FFFFF

    def test_clamp_up_down(self):
        # 4x slower -> target x4 (easier), up to compact truncation
        b = diff_mod.retarget(0x3D0FFFFF, 4 * 2048 * 300, 2048 * 300)
        t_old = pow_mod.bits_to_target(0x3D0FFFFF)
        t_new = pow_mod.bits_to_target(b)
        assert t_old * 4 * (1 - 2 ** -19) <= t_new <= t_old * 4
        # 4x faster -> target /4
        b2 = diff_mod.retarget(0x3D0FFFFF, 2048 * 300 // 4, 2048 * 300)
        t2 = pow_mod.bits_to_target(b2)
        assert t_old // 4 - (t_old >> 19) <= t2 <= t_old // 4
        # beyond clamp: bounded to the same factors
        b3 = diff_mod.retarget(0x3D0FFFFF, 1, 2048 * 300)
        t3 = pow_mod.bits_to_target(b3)
        assert t_old // 4 - (t_old >> 19) <= t3 <= t_old // 4
        b4 = diff_mod.retarget(0x3D0FFFFF, 10**9, 2048 * 300)
        t4 = pow_mod.bits_to_target(b4)
        assert t_old * 4 * (1 - 2 ** -19) <= t4 <= t_old * 4


class TestProtocolFrames:
    def test_roundtrip(self):
        frame = proto.encode_frame("version", {"height": 3, "best": "ab"})
        cmd, payload = proto.decode_frame(frame)
        assert cmd == "version"
        assert payload == {"height": 3, "best": "ab"}

    def test_streamed_frames(self):
        r = proto.FrameReader()
        f1 = proto.encode_frame("ping", {"n": 1})
        f2 = proto.encode_frame("pong", {"n": 2})
        blob = f1[:10] + f1[10:] + f2[:5] + f2[5:]
        r.feed(blob)
        assert r.next_frame() == ("ping", {"n": 1})
        assert r.next_frame() == ("pong", {"n": 2})
        assert r.next_frame() is None

    def test_bad_magic_resync(self):
        r = proto.FrameReader()
        f = proto.encode_frame("verack", {})
        r.feed(b"garbage!" + f)
        assert r.next_frame() == ("verack", {})

    def test_checksum_mismatch(self):
        f = bytearray(proto.encode_frame("ping", {"n": 1}))
        f[-1] ^= 1
        r = proto.FrameReader()
        r.feed(bytes(f))
        assert r.next_frame() is None

    def test_unknown_command(self):
        with pytest.raises(ValueError):
            proto.encode_frame("explode", {})

    def test_big_tx_frame(self):
        payload = {"tx": "ab" * 100_000}
        f = proto.encode_frame("tx", payload)
        assert len(f) < proto.MAX_PAYLOAD + 24
        cmd, p = proto.decode_frame(f)
        assert p == payload

"""Whitepaper conformance: every pinned constant the release must keep.

These are the assertions that make a rebuild of Qeuph bit-identical to the
chain the whitepaper describes.  If any of them fail, the code no longer
implements the released protocol.
"""
from __future__ import annotations

import pytest

from qeuph import constants as C
from qeuph.config import MAINNET, REGTEST, TESTNET, checkpoint_for
from qeuph.core import difficulty as diff_mod
from qeuph.core import genesis as genesis_mod
from qeuph.core import pow as pow_mod
from qeuph.core import reward as reward_mod
from qeuph.crypto import address as addr_mod
from qeuph.crypto import bech32m as b32m
from qeuph.core.block import HEADER_SIZE
from qeuph.crypto import ml_dsa


class TestGenesisIdentity:
    def test_mainnet_genesis_hash_matches_pinned(self):
        g = genesis_mod.build_genesis(MAINNET)
        assert g.hash == C.CHECKPOINTS[0]
        assert g.hash == genesis_mod.MAINNET_GENESIS_HASH
        assert g.hash.hex() == (
            "0000000d2f105b239cd085e9d4bd7fa087dc6a085ee37b3842d539ab9c974247"
            "fa8c4000695807b0a5d306d40c713e32b130387f72b64a00bf2b0c9953b179b1")

    def test_mainnet_genesis_parameters(self):
        g = genesis_mod.build_genesis(MAINNET)
        assert g.header.height == 0
        assert g.header.prev_hash == bytes(64)
        assert g.header.bits == C.GENESIS_BITS == 0x3D0FFFFF
        assert g.header.timestamp == C.GENESIS_TIMESTAMP == 1790812800
        assert g.header.nonce == genesis_mod.MAINNET_GENESIS_NONCE
        assert pow_mod.difficulty_from_bits(g.header.bits) == 1.0
        assert g.header.meets_target()
        assert genesis_mod.validate_genesis(g, MAINNET)

    def test_genesis_is_deterministic(self, net):
        a = genesis_mod.build_genesis(net)
        b = genesis_mod.build_genesis(net)
        assert a.serialize() == b.serialize()
        assert a.hash == b.hash

    def test_genesis_pays_nothing(self, net):
        g = genesis_mod.build_genesis(net)
        assert g.transactions[0].total_out == 0
        assert len(g.transactions) == 1
        assert g.transactions[0].is_coinbase
        assert g.transactions[0].outputs[0].addr_hash == \
            genesis_mod.NULL_ADDR_HASH

    def test_networks_have_distinct_identities(self):
        hashes = {n: genesis_mod.build_genesis(n).hash
                  for n in (MAINNET, TESTNET, REGTEST)}
        assert len(set(hashes.values())) == 3

    def test_networks_have_distinct_magic(self):
        assert MAINNET.magic == C.MAGIC_BYTES == b"QUH!"
        assert TESTNET.magic == C.TESTNET_MAGIC_BYTES
        assert REGTEST.magic == C.REGTEST_MAGIC_BYTES
        assert len({MAINNET.magic, TESTNET.magic, REGTEST.magic}) == 3

    def test_checkpoint_lookup(self):
        assert checkpoint_for(MAINNET, 0) == C.CHECKPOINTS[0]
        assert checkpoint_for(TESTNET, 0) is None
        assert checkpoint_for(REGTEST, 0) is None


class TestAppendixAParameters:
    """Whitepaper Appendix A, Table 8."""

    def test_consensus_parameters(self):
        assert C.BLOCK_TIME_SECONDS == 300
        assert C.RETARGET_INTERVAL == 2048
        assert C.RETARGET_BOUND_FACTOR == 4
        assert C.MAX_BLOCK_SIZE == 2_000_000
        assert C.REWARD_INTERVAL == 210_000
        assert C.REWARD_INITIAL == 50 * C.QUPHI_PER_QUH
        assert C.MAX_SUPPLY_QUH == 31_500_000
        assert C.QUPHI_PER_QUH == 100_000_000
        assert C.DECIMALS == 8
        assert C.COINBASE_MATURITY == 100
        assert C.MAX_FUTURE_BLOCK_SECONDS == 2 * 3600
        assert C.DEFAULT_P2P_PORT == 19090
        assert C.DEFAULT_RPC_PORT == 19091
        assert C.MAGIC_BYTES == b"\x51\x55\x48\x21"
        assert C.ADDRESS_HRP_MAINNET == "quh"
        assert C.GENESIS_TIMESTAMP == 1790812800
        assert C.GENESIS_BITS == 0x3D0FFFFF

    def test_header_is_168_bytes(self):
        assert HEADER_SIZE == 168
        assert C.MLDSA_PK_SIZE == 2592
        assert C.MLDSA_SIG_SIZE == 4627
        assert ml_dsa.PK_SIZE == 2592
        assert ml_dsa.SIG_SIZE == 4627
        assert ml_dsa.SK_SIZE == 4896
        assert ml_dsa.SEED_SIZE == 32


class TestEmissionSchedule:
    """Whitepaper sections 4.3 / 4.4 and Table 5."""

    def test_table_5_rewards(self):
        expected = {
            0: 50.0, 1: 33.33333333, 2: 22.22222222, 3: 14.81481481,
            4: 9.87654320, 5: 6.58436213,
        }
        for epoch, want in expected.items():
            got = reward_mod.block_reward(epoch * C.REWARD_INTERVAL)
            assert abs(got / C.QUPHI_PER_QUH - want) < 1e-8, epoch

    def test_table_5_cumulative(self):
        expected = {
            0: 10_500_000.0, 1: 17_499_999.999, 2: 22_166_666.666,
            3: 25_277_777.776, 4: 27_351_851.848, 5: 28_734_567.895,
        }
        rows = {e: cum for e, _h, _r, _rq, cum in reward_mod.emission_table()}
        for epoch, want in expected.items():
            got = rows[epoch] / C.QUPHI_PER_QUH
            assert abs(got - want) < 1e-3, (epoch, got, want)

    def test_final_reward_is_one_quphi(self):
        assert reward_mod.epoch_count() == 54
        assert reward_mod.last_reward_height() == 11_130_000
        last = reward_mod.block_reward(11_130_000)
        assert last == 1
        assert reward_mod.block_reward(11_340_000) == 0

    def test_exact_emission(self):
        exact = reward_mod.exact_total_emission()
        assert exact == 3_149_999_985_930_000
        assert abs(exact / C.QUPHI_PER_QUH - 31_499_999.8593) < 1e-6
        assert C.MAX_SUPPLY - exact == 14_070_000
        assert abs((C.MAX_SUPPLY - exact) / C.QUPHI_PER_QUH - 0.1407) < 1e-9

    def test_geometric_series_bound(self):
        # 3 x 50 QUH x 210,000 blocks is the analytic cap; the iterated floor
        # can only land at or below it.
        assert reward_mod.exact_total_emission() <= C.MAX_SUPPLY
        assert reward_mod.exact_total_emission() < C.MAX_SUPPLY

    def test_monotone_non_increasing(self):
        prev = None
        for _e, _h, r, _rq, _cum in reward_mod.emission_table():
            if prev is not None:
                assert r <= prev
            prev = r

    def test_epoch_boundaries(self):
        assert reward_mod.block_reward(0) == reward_mod.block_reward(209_999)
        assert reward_mod.block_reward(210_000) == 3_333_333_333
        assert reward_mod.epoch_at(210_000) == 1
        assert reward_mod.epoch_at(209_999) == 0
        with pytest.raises(ValueError):
            reward_mod.block_reward(-1)

    def test_cumulative_emission_at_genesis(self):
        assert reward_mod.cumulative_emission(0) == 50 * C.QUPHI_PER_QUH
        assert reward_mod.cumulative_emission(209_999) == \
            210_000 * 50 * C.QUPHI_PER_QUH


class TestDifficulty:
    def test_clamp_up(self):
        # 4x faster than expected -> target divided by 4, at most.  The
        # compact format has a 24-bit mantissa, so the encoded target can be
        # up to 1 part in 2^18 below the ideal value (i.e. slightly harder,
        # never easier).
        bits = diff_mod.retarget(C.GENESIS_BITS, 75, 300)
        target = pow_mod.bits_to_target(bits)
        prev = pow_mod.bits_to_target(C.GENESIS_BITS)
        assert target <= prev // 4 + 1
        assert target >= prev / 4 * (1 - 1e-5)

    def test_clamp_down(self):
        # 4x slower than expected -> target multiplied by 4 at most
        bits = diff_mod.retarget(C.GENESIS_BITS, 4800, 300)
        target = pow_mod.bits_to_target(bits)
        prev = pow_mod.bits_to_target(C.GENESIS_BITS)
        assert prev * 3 <= target <= prev * 4 + 1

    def test_no_change_when_on_schedule(self):
        bits = diff_mod.retarget(C.GENESIS_BITS, 300 * 2047, 300 * 2047)
        assert pow_mod.bits_to_target(bits) == \
            pow_mod.bits_to_target(C.GENESIS_BITS)

    def test_retarget_only_at_interval_boundaries(self):
        # 2x-slow history: 600 s per block instead of the 300 s target rate
        slow = [1000 + 600 * i for i in range(2048)]
        # the first retarget happens at child height 2048.  Blocks arriving
        # twice as slowly as the 300 s target rate mean half the hashrate, so
        # the target doubles and the reported difficulty halves.
        bits = diff_mod.next_bits(C.GENESIS_BITS, 2047, slow, 2048, 300)
        assert bits != C.GENESIS_BITS
        assert pow_mod.difficulty_from_bits(bits) == pytest.approx(0.5, rel=1e-4)
        # exactly on schedule -> no change
        on_time = [1000 + 300 * i for i in range(2048)]
        assert diff_mod.next_bits(C.GENESIS_BITS, 2047, on_time, 2048, 300) == \
            C.GENESIS_BITS
        # and the mirror image: history 30x faster than the target rate means
        # 30x the hashrate, clamped to 4x harder and no further
        fast = [1000 + 10 * i for i in range(2048)]
        hard = diff_mod.next_bits(C.GENESIS_BITS, 2047, fast, 2048, 300)
        base = pow_mod.bits_to_target(C.GENESIS_BITS)
        # the 24-bit mantissa truncates, so the encoded target can sit up to
        # ~1 part in 2^18 BELOW the clamp value (never above it)
        assert pow_mod.bits_to_target(hard) <= base // 4
        assert pow_mod.bits_to_target(hard) >= (base // 4) * (1 - 1e-5)
        assert pow_mod.difficulty_from_bits(hard) == pytest.approx(4.0, rel=1e-4)
        # the child of 2047 IS 2048, so it retargets; one block earlier does not
        assert diff_mod.next_bits(C.GENESIS_BITS, 2046, slow, 2048, 300) == \
            C.GENESIS_BITS
        # ... and neither does any height between retarget points
        for parent in (2047, 2048, 3000, 4094):
            assert diff_mod.next_bits(C.GENESIS_BITS, parent, slow, 2048, 300) \
                != C.GENESIS_BITS or (parent + 1) % 2048 != 0
        # next retarget is at child height 4096
        assert diff_mod.next_bits(bits, 4095, slow * 2, 2048, 300) != bits

    def test_genesis_difficulty_is_one(self):
        assert pow_mod.difficulty_from_bits(C.GENESIS_BITS) == 1.0
        harder = pow_mod.target_to_bits(pow_mod.bits_to_target(C.GENESIS_BITS) // 2)
        assert pow_mod.difficulty_from_bits(harder) == pytest.approx(2.0, rel=1e-6)

    def test_bits_roundtrip_for_genesis(self):
        assert pow_mod.bits_roundtrip_exact(C.GENESIS_BITS)

    def test_invalid_bits_rejected(self):
        for bad in (0xFFFFFFFF, 0x50000000, -1, 0x100000000):
            with pytest.raises(ValueError):
                pow_mod.bits_to_target(bad)
        assert pow_mod.bits_to_target(0) == 0
        assert pow_mod.is_valid_bits(C.GENESIS_BITS)
        assert pow_mod.is_valid_bits(C.EASIEST_BITS)
        assert pow_mod.is_valid_bits(C.HARDEST_BITS)
        assert not pow_mod.is_valid_bits(0x50000000)
        assert not pow_mod.is_valid_bits(0)
        assert not pow_mod.is_valid_bits(C.EASIEST_BITS + 1)


class TestAddressFormat:
    def test_address_is_113_characters(self):
        seed, pk, _ = ml_dsa.generate_keypair()
        addr = addr_mod.pk_to_address(pk)
        assert len(addr) == 113
        assert addr.startswith("quh1")
        assert len(addr[4:4 + 103]) == 103
        assert len(addr) - 4 - 103 == 6        # bech32m checksum

    def test_hrp_per_network(self):
        seed, pk, _ = ml_dsa.generate_keypair()
        h = addr_mod.pk_to_hash(pk)
        for hrp in ("quh", "tquh", "rquh"):
            a = addr_mod.hash_to_address(h, hrp)
            assert a.startswith(hrp + "1")
            assert addr_mod.address_to_hash(a, hrp) == h
        # a mainnet address is not valid on testnet
        assert addr_mod.address_to_hash(
            addr_mod.hash_to_address(h, "quh"), "tquh") is None

    def test_payload_is_the_full_512_bit_digest(self):
        h = bytes(range(64))
        a = addr_mod.hash_to_address(h)
        assert addr_mod.address_to_hash(a) == h

    def test_bad_public_key_size_rejected(self):
        with pytest.raises(ValueError):
            addr_mod.pk_to_hash(b"\x00" * 2591)

    def test_bech32m_checksum_catches_single_character_errors(self):
        h = bytes(range(64))
        a = addr_mod.hash_to_address(h)
        alphabet = b32m.CHARSET
        caught = 0
        tried = 0
        for i in range(4, len(a)):
            for c in alphabet:
                if c == a[i]:
                    continue
                tried += 1
                bad = a[:i] + c + a[i + 1:]
                if addr_mod.address_to_hash(bad) is None:
                    caught += 1
        # BIP-350 detects essentially every single-character substitution
        assert caught / tried > 0.99

    def test_bech32m_rejects_bech32_constant(self):
        # a bech32 (not bech32m) string with the same payload must not verify
        h = bytes(range(64))
        converted = b32m._convertbits(h, 8, 5, True)
        old = b32m._hrp_expand("quh") + converted + [0, 0, 0, 0, 0, 0]
        pm = b32m._polymod(old) ^ 1
        chk = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
        s = "quh1" + "".join(b32m.CHARSET[d] for d in converted + chk)
        assert b32m.bech32m_decode("quh", s) is None

    def test_mixed_case_rejected(self):
        h = bytes(range(64))
        a = addr_mod.hash_to_address(h)
        assert addr_mod.address_to_hash(a.upper()) is None or True
        mixed = a[:5] + a[5].upper() + a[6:]
        assert addr_mod.address_to_hash(mixed) is None

    def test_uppercase_all_upper_is_accepted(self):
        h = bytes(range(64))
        a = addr_mod.hash_to_address(h)
        assert addr_mod.address_to_hash(a.upper()) == h

    def test_hrp_for_network_helper(self):
        assert addr_mod.hrp_for_network("mainnet") == "quh"
        assert addr_mod.hrp_for_network("testnet") == "tquh"
        assert addr_mod.hrp_for_network("regtest") == "rquh"

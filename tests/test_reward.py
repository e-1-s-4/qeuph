"""Reward schedule ("two-thirding") tests."""
from qeuph import constants as C
from qeuph.core import reward as reward_mod


class TestReward:
    def test_initial_reward(self):
        assert reward_mod.block_reward(0) == 50 * C.QUPHI_PER_QUH
        assert reward_mod.block_reward(1) == 50 * C.QUPHI_PER_QUH
        assert reward_mod.block_reward(209_999) == 50 * C.QUPHI_PER_QUH

    def test_epoch_boundary_floor(self):
        # 50 * 2/3 = 33.33333333 QUH -> floored in quphi
        assert reward_mod.block_reward(210_000) == 3_333_333_333
        # 50 * (2/3)^2 = 22.22222222 QUH
        assert reward_mod.block_reward(420_000) == 2_222_222_222
        # 50 * (2/3)^3 = 14.81481481 QUH
        assert reward_mod.block_reward(630_000) == 1_481_481_481
        # whitepaper sequence (quphi): 50 -> 33.3333.. -> 22.2222.. -> 14.8148..
        seq = [reward_mod.block_reward(e * 210_000) for e in range(4)]
        assert seq == [5_000_000_000, 3_333_333_333, 2_222_222_222, 1_481_481_481]

    def test_monotonic_decrease(self):
        prev = None
        for h in range(0, 210_000 * 60, 210_000):
            r = reward_mod.block_reward(h)
            if prev is not None:
                assert r <= prev
                if r < prev:
                    assert r == (prev * 2) // 3 or r == 0
            prev = r

    def test_reaches_zero(self):
        # iterative flooring: last nonzero epoch is 53 (1 quphi), zero from 54
        assert reward_mod.block_reward(53 * 210_000) == 1
        assert reward_mod.block_reward(54 * 210_000) == 0
        assert reward_mod.block_reward(100 * 210_000) == 0

    def test_supply_never_exceeds_cap(self):
        total = reward_mod.exact_total_emission()
        assert total <= C.MAX_SUPPLY
        assert total > C.MAX_SUPPLY - C.QUPHI_PER_QUH  # within 1 QUH of cap
        # exact known value for the iterative schedule
        assert total == 3_149_999_985_930_000

    def test_emission_table(self):
        rows = reward_mod.emission_table()
        assert rows[0][0] == 0 and rows[0][2] == 5_000_000_000
        assert all(rows[i][2] >= rows[i + 1][2] for i in range(len(rows) - 1))
        assert rows[-1][2] == 1     # last non-zero epoch reward: 1 quphi

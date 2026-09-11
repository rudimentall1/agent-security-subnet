"""Regression tests for the chain-enforced set_weights rate limit.

Confirmed live against testnet 557: the validator loop attempted
set_weights every cycle (a few blocks apart) and was rejected almost every
time with a ChainError ("Weights on netuid 557 were last set X blocks ago;
the rate limit is 100 blocks"). subnet_cycle now checks the on-chain rate
limit and skips the doomed attempt instead of hitting the chain with a
transaction that's guaranteed to fail.
"""

import unittest
from unittest.mock import AsyncMock, Mock, patch

from bittensor_subnet.run_validator import subnet_cycle
from bittensor_subnet.validator import MinerEndpoint, ValidatorConfig
from subnet.protocol import VerificationResult


def make_verified_result(reproduction_key: str) -> VerificationResult:
    return VerificationResult(
        verdict="VERIFIED",
        severity="high",
        reproducible=True,
        policy_violation=True,
        impact_score=0.9,
        novelty_score=0.9,
        efficiency_score=0.9,
        security_score=0.775,
        duplicate=False,
        reason="ok",
        reproduction_key=reproduction_key,
    )


class TestSubnetCycleRespectsWeightsRateLimit(unittest.IsolatedAsyncioTestCase):
    def _base_mocks(self):
        adapter = Mock()
        adapter.miner_endpoints.return_value = [
            (1, MinerEndpoint(hotkey_ss58="5Miner1", url="http://127.0.0.1:8091")),
        ]
        adapter.aggregate_scores.return_value = {1: 0.775}

        validator = Mock()
        validator.evaluate = AsyncMock(return_value=make_verified_result("key-abc"))

        config = ValidatorConfig(validator_hotkey_ss58="5Validator", netuid=557, network="test")
        return adapter, validator, config

    async def test_skips_set_weights_when_rate_limited(self):
        adapter, validator, config = self._base_mocks()
        adapter.weights_rate_limit_blocks.return_value = 100
        adapter.own_last_weights_update_block.return_value = 7979794  # set 30 blocks ago

        fake_sub = Mock()
        fake_sub.block = 7979824  # 30 blocks after last set -> still rate-limited

        with patch("bittensor_subnet.run_validator.bt.Subtensor", return_value=fake_sub):
            await subnet_cycle(validator, adapter, config, cycle=1)

        adapter.set_weights.assert_not_called()

    async def test_attempts_set_weights_once_rate_limit_window_has_passed(self):
        adapter, validator, config = self._base_mocks()
        adapter.weights_rate_limit_blocks.return_value = 100
        adapter.own_last_weights_update_block.return_value = 7979794
        adapter.set_weights.return_value = "ok"

        fake_sub = Mock()
        fake_sub.block = 7979900  # 106 blocks later -> past the 100-block limit

        with patch("bittensor_subnet.run_validator.bt.Subtensor", return_value=fake_sub):
            await subnet_cycle(validator, adapter, config, cycle=1)

        adapter.set_weights.assert_called_once()

    async def test_attempts_set_weights_when_never_set_before(self):
        """own_last_weights_update_block()=None (never registered/never set)
        must not be treated as "just set" -- it must not block the first
        real attempt."""
        adapter, validator, config = self._base_mocks()
        adapter.weights_rate_limit_blocks.return_value = 100
        adapter.own_last_weights_update_block.return_value = None
        adapter.set_weights.return_value = "ok"

        fake_sub = Mock()
        fake_sub.block = 7979824

        with patch("bittensor_subnet.run_validator.bt.Subtensor", return_value=fake_sub):
            await subnet_cycle(validator, adapter, config, cycle=1)

        adapter.set_weights.assert_called_once()

    async def test_attempts_set_weights_when_rate_limit_unreadable(self):
        """weights_rate_limit_blocks()=None (read failed) must fail open --
        an optional check failing must not permanently block weight-setting."""
        adapter, validator, config = self._base_mocks()
        adapter.weights_rate_limit_blocks.return_value = None
        adapter.own_last_weights_update_block.return_value = 7979794
        adapter.set_weights.return_value = "ok"

        fake_sub = Mock()
        fake_sub.block = 7979824

        with patch("bittensor_subnet.run_validator.bt.Subtensor", return_value=fake_sub):
            await subnet_cycle(validator, adapter, config, cycle=1)

        adapter.set_weights.assert_called_once()


if __name__ == "__main__":
    unittest.main()

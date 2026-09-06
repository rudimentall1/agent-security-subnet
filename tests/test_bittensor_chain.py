import unittest
from unittest.mock import Mock, patch

from bittensor_subnet.chain import BittensorChainAdapter, ChainConfig
from subnet.protocol import VerificationResult


def result(score: float) -> VerificationResult:
    return VerificationResult(
        verdict="VERIFIED",
        severity="HIGH",
        reproducible=True,
        policy_violation=True,
        impact_score=1.0,
        novelty_score=1.0,
        efficiency_score=1.0,
        security_score=score,
        duplicate=False,
        reason="test",
    )


class TestBittensorChain(unittest.TestCase):
    def test_aggregate_scores_averages_validator_rewards(self):
        scores = BittensorChainAdapter.aggregate_scores(
            {
                1: [result(0.8), result(0.4)],
                2: [result(0.2)],
                3: [],
            }
        )
        self.assertEqual(scores, {1: 0.6, 2: 0.2, 3: 0.0})

    def test_set_weights_normalizes_scores_and_uses_v11_intent(self):
        wallet = Mock()
        adapter = BittensorChainAdapter(
            wallet,
            ChainConfig(netuid=7, network="test", weights_version=3),
        )
        fake_subtensor = Mock()
        fake_subtensor.execute.return_value = "submitted"

        with patch("bittensor_subnet.chain.bt.Subtensor", return_value=fake_subtensor), \
             patch("bittensor_subnet.chain.bt.SetWeights") as set_weights:
            set_weights.return_value = "intent"
            self.assertEqual(adapter.set_weights({1: 1.0, 2: 3.0}), "submitted")

        set_weights.assert_called_once_with(
            netuid=7,
            weights={1: 0.25, 2: 0.75},
            version_key=3,
        )
        fake_subtensor.execute.assert_called_once_with("intent", wallet)

    def test_empty_scores_are_rejected(self):
        adapter = BittensorChainAdapter(Mock(), ChainConfig(netuid=7))
        with self.assertRaises(ValueError):
            adapter.set_weights({})


if __name__ == "__main__":
    unittest.main()

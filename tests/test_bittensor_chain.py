import unittest
from dataclasses import dataclass, field
from unittest.mock import Mock, patch

from bittensor_subnet.chain import BittensorChainAdapter, ChainConfig
from subnet.protocol import VerificationResult


@dataclass
class FakeNeuron:
    """Mirrors bittensor.reads.neurons.Neuron's real shape (11.1.0).

    Field names/types copied directly from the installed package source
    (bittensor/reads/neurons.py) rather than guessed, so this fixture stays
    honest about what sub.read("neurons", ...) actually returns.
    """

    uid: int
    hotkey: str
    coldkey: str
    active: bool
    validator_permit: bool
    last_update: int
    total_stake: object
    raw: dict = field(repr=False)


def fake_neuron(uid: int, *, hotkey: str, ip: int, port: int, active: bool = True) -> FakeNeuron:
    return FakeNeuron(
        uid=uid,
        hotkey=hotkey,
        coldkey="5FakeColdkey",
        active=active,
        validator_permit=False,
        last_update=0,
        total_stake=0,
        raw={"axon_info": {"ip": ip, "port": port}},
    )


def result(score: float, key: str | None = None) -> VerificationResult:
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
        reproduction_key=key,
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

    def test_aggregate_scores_deduplicates_same_exploit_across_validators_and_miners(self):
        scores = BittensorChainAdapter.aggregate_scores(
            {
                1: [result(0.8, "exploit-A"), result(0.6, "exploit-A")],
                2: [result(0.9, "exploit-A")],
                3: [result(0.4, "exploit-B")],
            }
        )

        # UID 2 wins exploit-A with 0.9. UID 1's two validator
        # confirmations are averaged, but the duplicate exploit is not paid
        # to UID 1. UID 3 keeps its independent finding.
        self.assertEqual(
            scores,
            {
                1: 0.0,
                2: 0.9,
                3: 0.4,
            },
        )

    def test_aggregate_scores_preserves_unkeyed_legacy_behavior(self):
        scores = BittensorChainAdapter.aggregate_scores(
            {
                1: [result(0.8), result(0.4)],
                2: [],
            }
        )
        self.assertEqual(scores, {1: 0.6, 2: 0.0})

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

    def test_metagraph_uses_read_not_removed_neurons_api(self):
        """Regression test for a confirmed-broken call.

        bittensor 11.1.0's Subtensor has no `.neurons` attribute and no
        `.metagraph()` method -- calling either raises AttributeError on
        every real invocation. `read("neurons", ...)` is the only working
        discovery API. This test fails loudly if the adapter regresses to
        the removed API.
        """
        adapter = BittensorChainAdapter(Mock(), ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])  # spec=[] means .neurons would raise
        fake_subtensor.read.return_value = [fake_neuron(1, hotkey="5A", ip=1, port=8091)]

        result = adapter.metagraph(sub=fake_subtensor)

        fake_subtensor.read.assert_called_once_with("neurons", netuid=557, lite=True)
        self.assertEqual(len(result), 1)

    def test_miner_endpoints_filters_unroutable_neurons_only(self):
        """Regression test pinned against real testnet-557 data.

        Verified live: every neuron on this subnet reports active=False,
        including miners with a real, working axon (non-zero ip:port,
        recently-updated block). Filtering on `active` (the original
        implementation) silently discarded every miner and produced
        registered_miners=0 despite miners being genuinely online. The
        only correct filter is routability itself (a resolvable axon
        endpoint), which also naturally excludes validators (their
        axon_info is all-zero -- they don't run an axon).
        """
        adapter = BittensorChainAdapter(Mock(), ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])
        fake_subtensor.read.return_value = [
            fake_neuron(1, hotkey="5Miner", ip=0x7F000001, port=8091, active=False),
            fake_neuron(2, hotkey="5Validator", ip=0, port=0, active=True),
            fake_neuron(3, hotkey="5NoAxon", ip=0, port=0, active=False),
        ]

        endpoints = adapter.miner_endpoints(sub=fake_subtensor)

        self.assertEqual(len(endpoints), 1)
        uid, endpoint = endpoints[0]
        self.assertEqual(uid, 1)
        self.assertEqual(endpoint.hotkey_ss58, "5Miner")
        self.assertEqual(endpoint.url, "http://127.0.0.1:8091")

    def test_metagraph_opens_its_own_connection_when_none_supplied(self):
        adapter = BittensorChainAdapter(Mock(), ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])
        fake_subtensor.read.return_value = []

        with patch("bittensor_subnet.chain.bt.Subtensor", return_value=fake_subtensor) as ctor:
            adapter.metagraph()

        ctor.assert_called_once_with(network="test")
        fake_subtensor.read.assert_called_once_with("neurons", netuid=557, lite=True)

    def test_real_testnet_557_snapshot_yields_three_miners(self):
        """Fixture captured live from testnet 557 on 2026-09-11 (5 neurons:
        2 validators with all-zero axon_info, 3 miners with real axons).
        This is what actually broke registered_miners=0 in production --
        keep this pinned to the real shape, not a convenient mock."""
        adapter = BittensorChainAdapter(Mock(), ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])
        fake_subtensor.read.return_value = [
            FakeNeuron(
                uid=0, hotkey="5DAjGJqHnRr3cm77gqLkKbHmhMe3mKPcBPhtChcf9y8VtgMh",
                coldkey="", active=False, validator_permit=True, last_update=0,
                total_stake=0, raw={"axon_info": {"ip": 0, "port": 0}},
            ),
            FakeNeuron(
                uid=1, hotkey="5DXcTqmJVUHMPMGmpnuzSVuLRqgwtPvU35mbNPZngomvbcFs",
                coldkey="", active=False, validator_permit=False, last_update=0,
                total_stake=0, raw={"axon_info": {"ip": 1307540773, "port": 8091}},
            ),
            FakeNeuron(
                uid=2, hotkey="5E7Qtz5T4Afojee9YfnRKhELF3KiT6DvrccBMubChbS3JMZs",
                coldkey="", active=False, validator_permit=False, last_update=0,
                total_stake=0, raw={"axon_info": {"ip": 1307540773, "port": 8092}},
            ),
            FakeNeuron(
                uid=3, hotkey="5CK4Rb717GnceKhZjPntXzEYvii7dJEV5PA5TqCbRVr8XdkJ",
                coldkey="", active=False, validator_permit=False, last_update=0,
                total_stake=0, raw={"axon_info": {"ip": 1307540773, "port": 8093}},
            ),
            FakeNeuron(
                uid=4, hotkey="5F4qAYRt6raq3uiXXiyzezhwjzqdVqaCkZY2zttihedMZjfx",
                coldkey="", active=False, validator_permit=True, last_update=0,
                total_stake=0, raw={"axon_info": {"ip": 0, "port": 0}},
            ),
        ]

        endpoints = adapter.miner_endpoints(sub=fake_subtensor)

        self.assertEqual(
            {uid for uid, _ in endpoints}, {1, 2, 3},
            "must discover exactly the 3 miners, excluding both validators",
        )
        endpoint_by_uid = dict(endpoints)
        self.assertEqual(endpoint_by_uid[1].url, "http://77.239.125.37:8091")
        self.assertEqual(endpoint_by_uid[2].url, "http://77.239.125.37:8092")
        self.assertEqual(endpoint_by_uid[3].url, "http://77.239.125.37:8093")


class TestWeightsRateLimit(unittest.TestCase):
    """Regression tests for the chain-enforced set_weights rate limit.

    Confirmed live against testnet 557: our validator loop attempted
    set_weights every ~3 blocks and was rejected almost every time with
    "Weights on netuid 557 were last set X blocks ago; the rate limit is
    100 blocks."
    """

    def test_weights_rate_limit_reads_dict_not_attribute(self):
        """subnet_hyperparameters returns a flat name->value dict (per
        bittensor/reads/subnets.py), not an attribute-bearing object like
        Neuron. Getting this wrong (e.g. getattr) would silently return
        None via the except-Exception fallback and this bug would never
        surface until a real chain call -- exactly like the neuron/active
        bugs above."""
        adapter = BittensorChainAdapter(Mock(), ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])
        fake_subtensor.read.return_value = {
            "weights_rate_limit": 100,
            "min_allowed_weights": 1,
        }

        result = adapter.weights_rate_limit_blocks(sub=fake_subtensor)

        fake_subtensor.read.assert_called_once_with(
            "subnet_hyperparameters", netuid=557
        )
        self.assertEqual(result, 100)

    def test_weights_rate_limit_fails_open_on_read_error(self):
        adapter = BittensorChainAdapter(Mock(), ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])
        fake_subtensor.read.side_effect = RuntimeError("chain unreachable")

        self.assertIsNone(adapter.weights_rate_limit_blocks(sub=fake_subtensor))

    def test_weights_rate_limit_fails_open_on_missing_key(self):
        adapter = BittensorChainAdapter(Mock(), ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])
        fake_subtensor.read.return_value = {"min_allowed_weights": 1}  # key absent

        self.assertIsNone(adapter.weights_rate_limit_blocks(sub=fake_subtensor))

    def test_own_last_weights_update_block_finds_own_hotkey(self):
        fake_wallet = Mock()
        fake_wallet.hotkey.ss58_address = "5F4qAYRt6raq3uiXXiyzezhwjzqdVqaCkZY2zttihedMZjfx"
        adapter = BittensorChainAdapter(fake_wallet, ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])
        fake_subtensor.read.return_value = [
            fake_neuron(1, hotkey="5SomeoneElse", ip=1, port=8091),
            FakeNeuron(
                uid=4, hotkey="5F4qAYRt6raq3uiXXiyzezhwjzqdVqaCkZY2zttihedMZjfx",
                coldkey="", active=False, validator_permit=True,
                last_update=7979794, total_stake=0,
                raw={"axon_info": {"ip": 0, "port": 0}},
            ),
        ]

        result = adapter.own_last_weights_update_block(sub=fake_subtensor)

        self.assertEqual(result, 7979794)

    def test_own_last_weights_update_block_none_when_not_registered(self):
        fake_wallet = Mock()
        fake_wallet.hotkey.ss58_address = "5NotInTheMetagraph"
        adapter = BittensorChainAdapter(fake_wallet, ChainConfig(netuid=557, network="test"))
        fake_subtensor = Mock(spec=["read"])
        fake_subtensor.read.return_value = [
            fake_neuron(1, hotkey="5SomeoneElse", ip=1, port=8091),
        ]

        self.assertIsNone(adapter.own_last_weights_update_block(sub=fake_subtensor))


if __name__ == "__main__":
    unittest.main()

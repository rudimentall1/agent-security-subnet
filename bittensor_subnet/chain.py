from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from typing import Iterable, Mapping

import bittensor as bt

from bittensor_subnet.validator import MinerEndpoint
from subnet.protocol import VerificationResult
from subnet.stateful_scoring import calculate_reward


@dataclass(frozen=True)
class ChainConfig:
    netuid: int
    network: str = "test"
    weights_version: int = 0


class BittensorChainAdapter:
    """Small v11 adapter for miner discovery and validator weight submission.

    Networking stays outside Bittensor's removed Axon/Dendrite stack. The chain
    stores miner identity and the published ip:port; this adapter only bridges
    that metadata to the HTTP validator and publishes final scores as weights.
    """

    def __init__(self, wallet: bt.Wallet, config: ChainConfig) -> None:
        self.wallet = wallet
        self.config = config

    def metagraph(self, sub: bt.Subtensor | None = None):
        """Return v11 neurons for this subnet.

        Uses ``Subtensor.read("neurons", ...)`` -- the only neuron-discovery
        API that actually exists on bittensor 11.1.0. ``Subtensor.neurons``
        and ``Subtensor.metagraph()`` were removed upstream and calling them
        raises ``AttributeError`` on every real invocation; this was verified
        directly against the installed 11.1.0 package.

        A caller-supplied ``sub`` lets the validator loop reuse a single
        connection across cycles instead of opening a new substrate
        connection on every call (see ``miner_endpoints``/``set_weights``).
        """
        sub = sub or bt.Subtensor(network=self.config.network)
        return sub.read("neurons", netuid=self.config.netuid, lite=True)

    @staticmethod
    def _axon_url(neuron) -> str | None:
        """Extract a usable endpoint from a v11 neuron raw payload."""
        raw = getattr(neuron, "raw", None)
        if not isinstance(raw, Mapping):
            return None

        axon = raw.get("axon_info")
        if not isinstance(axon, Mapping):
            return None

        ip = axon.get("ip")
        port = axon.get("port")
        if ip is None or port is None:
            return None

        try:
            port_int = int(port)
        except (TypeError, ValueError):
            return None

        if port_int <= 0:
            return None

        try:
            host = str(ipaddress.ip_address(int(ip)))
        except (TypeError, ValueError):
            return None

        if ipaddress.ip_address(host).is_unspecified:
            return None

        return f"http://{host}:{port_int}"

    def miner_endpoints(
        self, sub: bt.Subtensor | None = None
    ) -> list[tuple[int, MinerEndpoint]]:
        """Return registered neurons with a usable (routable) endpoint.

        Deliberately does NOT gate on neuron.active. Verified directly
        against testnet 557: all 5 neurons (2 validators, 3 miners) report
        active=False, including the 3 miners whose axon_info has a real,
        non-zero, recently-updated ip:port and are demonstrably reachable.
        Whatever `active` tracks on this SDK/network, it isn't "has a
        working axon" -- a real axon endpoint (_axon_url() returning
        non-None) already implies routability, which is the only thing
        this method actually needs to guarantee. The validators (whose
        axon_info is all-zero, as expected -- they don't run an axon) are
        correctly excluded by _axon_url() returning None, not by this flag.
        """
        result: list[tuple[int, MinerEndpoint]] = []

        for neuron in self.metagraph(sub=sub):
            hotkey = getattr(neuron, "hotkey", None)
            uid = getattr(neuron, "uid", None)
            url = self._axon_url(neuron)

            if not hotkey or uid is None or url is None:
                continue

            result.append(
                (int(uid), MinerEndpoint(hotkey_ss58=str(hotkey), url=url))
            )

        return result

    def weights_rate_limit_blocks(self, sub: bt.Subtensor | None = None) -> int | None:
        """Minimum blocks a hotkey must wait between successful set_weights
        calls on this subnet, read from on-chain hyperparameters
        (SubtensorModule.WeightsSetRateLimit).

        Discovered the hard way: our subnet_cycle previously attempted
        set_weights every cycle regardless of chain state and mostly got
        rejected with "Weights on netuid N were last set X blocks ago; the
        rate limit is Y blocks" -- confirmed live against testnet 557
        (Y=100). Returns None (fail open -- caller should not block
        weight-setting on a failed optional read) if the read fails.

        Note: subnet_hyperparameters returns a flat name->value dict, not an
        attribute-bearing object -- unlike Neuron. Mixing that up would have
        been a real, easy-to-make bug here.
        """
        sub = sub or bt.Subtensor(network=self.config.network)
        try:
            params = sub.read("subnet_hyperparameters", netuid=self.config.netuid)
            if not params:
                return None
            return int(params["weights_rate_limit"])
        except Exception:
            return None

    def own_last_weights_update_block(
        self, sub: bt.Subtensor | None = None
    ) -> int | None:
        """Block at which this validator's hotkey last had weights recorded
        (Neuron.last_update), used to decide whether attempting set_weights
        would just be rejected by the chain's rate limit. None if our
        hotkey isn't found in the current neuron set (e.g. not yet
        registered) or the read fails.
        """
        sub = sub or bt.Subtensor(network=self.config.network)
        own_hotkey = self.wallet.hotkey.ss58_address
        try:
            for neuron in self.metagraph(sub=sub):
                if getattr(neuron, "hotkey", None) == own_hotkey:
                    return int(getattr(neuron, "last_update", 0))
        except Exception:
            return None
        return None

    @staticmethod
    def aggregate_scores(
        results_by_uid: Mapping[int, Iterable[VerificationResult]],
    ) -> dict[int, float]:
        """Aggregate validator rewards with semantic exploit deduplication.

        Multiple validators confirming the same finding for the same miner are
        averaged. If multiple miners submit the same reproduction key, only
        the miner with the strongest validated reward for that key receives
        that reward. Results without a reproduction key retain the legacy
        per-UID averaging behavior.
        """
        normalized: dict[int, list[VerificationResult]] = {
            int(uid): list(results)
            for uid, results in results_by_uid.items()
        }

        scores: dict[int, float] = {
            uid: 0.0 for uid in normalized
        }

        # Preserve legacy behavior for results that predate reproduction keys.
        for uid, results in normalized.items():
            unkeyed = [
                calculate_reward(result)
                for result in results
                if not result.reproduction_key
            ]
            if unkeyed:
                scores[uid] += sum(unkeyed) / len(unkeyed)

        # Group keyed validations by semantic exploit identity.
        by_key: dict[str, dict[int, list[float]]] = {}
        for uid, results in normalized.items():
            for result in results:
                key = result.reproduction_key
                if not key:
                    continue
                by_key.setdefault(key, {}).setdefault(uid, []).append(
                    calculate_reward(result)
                )

        # Each reproduction key is paid once. Validator confirmations for a
        # given UID are averaged; ties are resolved deterministically by UID.
        for key, candidates in by_key.items():
            winner_uid, winner_values = min(
                candidates.items(),
                key=lambda item: (
                    -sum(item[1]) / len(item[1]),
                    item[0],
                ),
            )
            scores[winner_uid] += sum(winner_values) / len(winner_values)

        return {
            uid: round(score, 12)
            for uid, score in scores.items()
        }

    def set_weights(self, scores_by_uid: Mapping[int, float]):
        """Submit normalized validator scores using the v11 SetWeights intent."""
        scores = {int(uid): max(0.0, float(score)) for uid, score in scores_by_uid.items()}
        if not scores:
            raise ValueError("cannot submit empty validator weights")

        total = sum(scores.values())
        if total <= 0.0:
            weights = {uid: 0.0 for uid in scores}
        else:
            weights = {uid: score / total for uid, score in scores.items()}

        sub = bt.Subtensor(network=self.config.network)
        intent = bt.SetWeights(
            netuid=self.config.netuid,
            weights=weights,
            version_key=self.config.weights_version,
        )
        return sub.execute(intent, self.wallet)

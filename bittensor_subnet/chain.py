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

    def metagraph(self):
        """Return v11 neurons for this subnet."""
        sub = bt.Subtensor(network=self.config.network)
        return sub.neurons.all(self.config.netuid)

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

    def miner_endpoints(self) -> list[tuple[int, MinerEndpoint]]:
        """Return active registered neurons with usable endpoints."""
        result: list[tuple[int, MinerEndpoint]] = []

        for neuron in self.metagraph():
            if not bool(getattr(neuron, "active", False)):
                continue

            hotkey = getattr(neuron, "hotkey", None)
            uid = getattr(neuron, "uid", None)
            url = self._axon_url(neuron)

            if not hotkey or uid is None or url is None:
                continue

            result.append(
                (int(uid), MinerEndpoint(hotkey_ss58=str(hotkey), url=url))
            )

        return result

    @staticmethod
    def aggregate_scores(
        results_by_uid: Mapping[int, Iterable[VerificationResult]],
    ) -> dict[int, float]:
        """Average validated rewards per UID; never score from miner claims."""
        scores: dict[int, float] = {}
        for uid, results in results_by_uid.items():
            values = [calculate_reward(result) for result in results]
            scores[int(uid)] = round(sum(values) / len(values), 12) if values else 0.0
        return scores

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

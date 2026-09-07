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

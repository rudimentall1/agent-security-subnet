from __future__ import annotations

import asyncio
import os

import bittensor as bt

from bittensor_subnet.chain import BittensorChainAdapter
from bittensor_subnet.validator import (
    MinerEndpoint,
    StatefulHTTPValidator,
    ValidatorClient,
    ValidatorConfig,
    make_benchmark_tasks,
)


async def main() -> None:
    wallet = bt.Wallet(
        name=os.getenv("VERITENSOR_WALLET", "veritensor"),
        hotkey=os.getenv("VERITENSOR_VALIDATOR_HOTKEY", "validator"),
    )

    config = ValidatorConfig.from_env()
    client = ValidatorClient(wallet, config)
    validator = StatefulHTTPValidator(client)

    endpoint = MinerEndpoint(
        hotkey_ss58=os.getenv(
            "VERITENSOR_MINER_HOTKEY_SS58",
            wallet.hotkey.ss58_address,
        ),
        url=os.getenv("VERITENSOR_MINER_URL", "http://127.0.0.1:8091"),
    )

    count = max(1, int(os.getenv("VERITENSOR_BENCHMARK_COUNT", "3")))
    tasks = make_benchmark_tasks(count)

    results = await asyncio.gather(
        *(validator.evaluate(endpoint, task) for task in tasks)
    )

    rewards = [result.security_score for result in results]

    print("=== VERITENSOR VALIDATOR RUN ===")
    for task, result in zip(tasks, results):
        print(
            f"{task.task_id}: "
            f"verdict={result.verdict} "
            f"severity={result.severity} "
            f"reward={result.security_score:.6f} "
            f"reproducible={result.reproducible}"
        )

    adapter = BittensorChainAdapter(
        wallet,
        config=__import__("bittensor_subnet.chain", fromlist=["ChainConfig"]).ChainConfig(
            netuid=config.netuid,
            network=config.network,
        ),
    )

    scores = adapter.aggregate_scores(
        {0: results}
    )

    total = sum(scores.values())
    weights = (
        {uid: round(score / total, 6) for uid, score in scores.items()}
        if total > 0
        else scores
    )

    print(f"aggregated_scores={scores}")
    print(f"normalized_weights={weights}")


if __name__ == "__main__":
    asyncio.run(main())

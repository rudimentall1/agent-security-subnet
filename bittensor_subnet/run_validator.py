from __future__ import annotations

import asyncio
import os

import bittensor as bt

from bittensor_subnet.chain import BittensorChainAdapter, ChainConfig
from bittensor_subnet.validator import (
    MinerEndpoint,
    StatefulHTTPValidator,
    ValidatorClient,
    ValidatorConfig,
    make_benchmark_tasks,
)


def build_adapter(wallet: bt.Wallet, config: ValidatorConfig) -> BittensorChainAdapter:
    return BittensorChainAdapter(
        wallet,
        ChainConfig(
            netuid=config.netuid,
            network=config.network,
            weights_version=int(os.getenv("VERITENSOR_WEIGHTS_VERSION", "0")),
        ),
    )


async def evaluate_endpoint(
    validator: StatefulHTTPValidator,
    uid: int,
    endpoint: MinerEndpoint,
    tasks,
) -> tuple[int, list]:
    results = []

    for task in tasks:
        try:
            result = await validator.evaluate(endpoint, task)
        except Exception as exc:
            print(
                f"uid={uid} task={task.task_id} "
                f"status=error error={type(exc).__name__}: {exc}"
            )
            continue

        results.append(result)
        print(
            f"uid={uid} task={task.task_id} "
            f"verdict={result.verdict} "
            f"reward={result.security_score:.6f} "
            f"reproducible={result.reproducible}"
        )

    return uid, results


async def benchmark_mode(
    validator: StatefulHTTPValidator,
    wallet: bt.Wallet,
    config: ValidatorConfig,
) -> None:
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

    print("=== VERITENSOR BENCHMARK ===")
    for task, result in zip(tasks, results):
        print(
            f"{task.task_id}: "
            f"verdict={result.verdict} "
            f"severity={result.severity} "
            f"reward={result.security_score:.6f} "
            f"reproducible={result.reproducible}"
        )


async def subnet_cycle(
    validator: StatefulHTTPValidator,
    adapter: BittensorChainAdapter,
    config: ValidatorConfig,
    cycle: int,
) -> None:
    endpoints = adapter.miner_endpoints()

    print(
        f"cycle={cycle} "
        f"registered_miners={len(endpoints)}"
    )

    if not endpoints:
        print("registered_miners=0 waiting_for_miners=true")
        return

    task_count = max(
        1,
        int(os.getenv("VERITENSOR_BENCHMARK_COUNT", "3")),
    )
    tasks = make_benchmark_tasks(task_count)

    evaluated = await asyncio.gather(
        *(
            evaluate_endpoint(validator, uid, endpoint, tasks)
            for uid, endpoint in endpoints
        )
    )

    results_by_uid = {
        uid: results
        for uid, results in evaluated
        if results
    }

    if not results_by_uid:
        print("scores={} set_weights=false reason=no_valid_results")
        return

    scores = adapter.aggregate_scores(results_by_uid)
    positive_scores = {
        uid: score
        for uid, score in scores.items()
        if score > 0.0
    }

    print(f"aggregated_scores={scores}")

    if not positive_scores:
        print("set_weights=false reason=no_positive_scores")
        return

    try:
        tx_result = adapter.set_weights(positive_scores)
    except Exception as exc:
        print(
            f"set_weights=false "
            f"error={type(exc).__name__}: {exc}"
        )
        return

    print(
        f"set_weights=true "
        f"weights={positive_scores} "
        f"result={tx_result}"
    )


async def subnet_mode(
    validator: StatefulHTTPValidator,
    wallet: bt.Wallet,
    config: ValidatorConfig,
) -> None:
    adapter = build_adapter(wallet, config)

    interval = max(
        30,
        int(os.getenv("VERITENSOR_LOOP_INTERVAL_SECONDS", "120")),
    )
    oneshot = os.getenv("VERITENSOR_ONESHOT", "0").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    cycle = 0

    while True:
        cycle += 1

        try:
            await subnet_cycle(
                validator,
                adapter,
                config,
                cycle,
            )
        except Exception as exc:
            print(
                f"cycle={cycle} status=error "
                f"error={type(exc).__name__}: {exc}"
            )

        if oneshot:
            break

        print(f"sleeping_seconds={interval}")
        await asyncio.sleep(interval)


async def main() -> None:
    wallet = bt.Wallet(
        name=os.getenv("VERITENSOR_WALLET", "veritensor"),
        hotkey=os.getenv("VERITENSOR_VALIDATOR_HOTKEY", "validator"),
    )

    config = ValidatorConfig.from_env(
        validator_hotkey_ss58=wallet.hotkey.ss58_address,
    )
    client = ValidatorClient(wallet, config)
    validator = StatefulHTTPValidator(client)

    mode = os.getenv(
        "VERITENSOR_VALIDATOR_MODE",
        "subnet",
    ).strip().lower()

    if mode == "benchmark":
        await benchmark_mode(
            validator,
            wallet,
            config,
        )
        return

    if mode != "subnet":
        raise ValueError(
            "VERITENSOR_VALIDATOR_MODE must be 'subnet' or 'benchmark'"
        )

    await subnet_mode(
        validator,
        wallet,
        config,
    )


if __name__ == "__main__":
    asyncio.run(main())

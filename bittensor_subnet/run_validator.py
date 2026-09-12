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
from subnet.oaa_bridge import issue_finding_attestation
from subnet.stateful_scoring import FindingCorpus


def build_adapter(wallet: bt.Wallet, config: ValidatorConfig) -> BittensorChainAdapter:
    return BittensorChainAdapter(
        wallet,
        ChainConfig(
            netuid=config.netuid,
            network=config.network,
            weights_version=int(os.getenv("VERITENSOR_WEIGHTS_VERSION", "0")),
        ),
    )


def _load_oaa_signing_config() -> tuple[str, bytes] | None:
    """Returns (issuer, private_key_pem) if OAA attestation is configured,
    else None. Opt-in: without VERITENSOR_OAA_PRIVATE_KEY_PATH set, no
    attestations are issued and nothing else about the validator loop
    changes."""
    key_path = os.getenv("VERITENSOR_OAA_PRIVATE_KEY_PATH", "").strip()
    if not key_path:
        return None
    issuer = os.getenv(
        "VERITENSOR_OAA_ISSUER",
        "https://github.com/rudimentall1/agent-security-subnet",
    )
    with open(key_path, "rb") as fh:
        private_key_pem = fh.read()
    return issuer, private_key_pem


def _persist_attestation(token: str, reproduction_key: str) -> str:
    out_dir = os.getenv("VERITENSOR_OAA_ATTESTATION_DIR", "evidence/attestations")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{reproduction_key}.jwt")
    with open(path, "w") as fh:
        fh.write(token)
    return path


async def evaluate_endpoint(
    validator: StatefulHTTPValidator,
    uid: int,
    endpoint: MinerEndpoint,
    tasks,
) -> tuple[int, list]:
    results = []
    oaa_config = _load_oaa_signing_config()

    for task in tasks:
        try:
            finding, result = await validator.evaluate(endpoint, task)
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

        if oaa_config is not None and result.verdict == "VERIFIED":
            issuer, private_key_pem = oaa_config
            token = issue_finding_attestation(
                task, finding, result,
                issuer=issuer, private_key_pem=private_key_pem,
            )
            if token is not None:
                path = _persist_attestation(token, result.reproduction_key)
                print(
                    f"uid={uid} task={task.task_id} "
                    f"oaa_attestation=issued path={path}"
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
    for task, (finding, result) in zip(tasks, results):
        print(
            f"{task.task_id}: "
            f"verdict={result.verdict} "
            f"severity={result.severity} "
            f"reward={result.security_score:.6f} "
            f"reproducible={result.reproducible}"
        )


EPOCH_BLOCKS = int(os.getenv("VERITENSOR_EPOCH_BLOCKS", "360"))  # ~1h at 10s/block


async def subnet_cycle(
    validator: StatefulHTTPValidator,
    adapter: BittensorChainAdapter,
    config: ValidatorConfig,
    cycle: int,
) -> None:
    # One connection per cycle, reused for discovery and epoch lookup, instead
    # of opening a fresh substrate connection per call.
    sub = bt.Subtensor(network=config.network)
    current_block = sub.block
    epoch = current_block // EPOCH_BLOCKS

    endpoints = adapter.miner_endpoints(sub=sub)

    print(
        f"cycle={cycle} "
        f"block={current_block} epoch={epoch} "
        f"registered_miners={len(endpoints)}"
    )

    if not endpoints:
        print("registered_miners=0 waiting_for_miners=true")
        return

    task_count = max(
        1,
        int(os.getenv("VERITENSOR_BENCHMARK_COUNT", "3")),
    )
    tasks = make_benchmark_tasks(task_count, epoch=epoch)

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

    rate_limit = adapter.weights_rate_limit_blocks(sub=sub)
    last_set_block = adapter.own_last_weights_update_block(sub=sub)
    if (
        rate_limit is not None
        and last_set_block is not None
        and last_set_block > 0
    ):
        blocks_since = current_block - last_set_block
        if blocks_since < rate_limit:
            print(
                f"set_weights=skipped reason=chain_rate_limit "
                f"blocks_since_last_set={blocks_since} "
                f"rate_limit_blocks={rate_limit} "
                f"retry_in_blocks={rate_limit - blocks_since}"
            )
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

    corpus_path = os.getenv("VERITENSOR_CORPUS_DB_PATH", "").strip()
    corpus = FindingCorpus(storage_path=corpus_path or None)

    validator = StatefulHTTPValidator(client, corpus=corpus)

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

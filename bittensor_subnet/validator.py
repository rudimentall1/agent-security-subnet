from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Iterable

import bittensor as bt
import httpx

from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    VerificationResult,
    build_task,
    make_reproduction_key,
)
from subnet.stateful_oracle import scenario_for_task
from subnet.stateful_target import build_target
from subnet.stateful_validator import StatefulValidator

from bittensor_subnet.protocol import FindingResponse, SecurityTaskRequest


@dataclass(frozen=True)
class MinerEndpoint:
    """A miner endpoint keyed by its on-chain hotkey identity."""

    hotkey_ss58: str
    url: str


@dataclass(frozen=True)
class ValidatorConfig:
    """Runtime settings for the validator-side HTTP client."""

    validator_hotkey_ss58: str
    request_timeout: float = 15.0
    max_concurrency: int = 16

    @classmethod
    def from_env(cls) -> "ValidatorConfig":
        hotkey = os.getenv("VERITENSOR_VALIDATOR_HOTKEY_SS58", "").strip()
        if not hotkey:
            raise ValueError("VERITENSOR_VALIDATOR_HOTKEY_SS58 is required")
        return cls(
            validator_hotkey_ss58=hotkey,
            request_timeout=float(os.getenv("VERITENSOR_REQUEST_TIMEOUT", "15")),
            max_concurrency=max(1, int(os.getenv("VERITENSOR_MAX_CONCURRENCY", "16"))),
        )


def task_to_request(task: SecurityTask) -> SecurityTaskRequest:
    return SecurityTaskRequest(
        task_id=task.task_id,
        target_name=task.target_name,
        target_version=task.target_version,
        objective=task.objective,
        max_steps=task.max_steps,
        allowed_tools=list(task.allowed_tools),
    )


def response_to_finding(
    response: FindingResponse,
    task: SecurityTask,
    miner_hotkey_ss58: str,
) -> ExploitFinding:
    """Convert an untrusted network response into a validator-owned finding.

    Identity, reproduction key and step count are derived/validated here rather
    than trusting miner-controlled metadata. In particular, a miner cannot
    manufacture a second identity or a collision-resistant key that differs
    from the trajectory the validator actually received.
    """
    trace = tuple(response.attack_trace)
    if response.task_id != task.task_id:
        raise ValueError("miner response task_id does not match request")
    if not trace:
        raise ValueError("miner returned an empty attack trace")
    if len(trace) > task.max_steps:
        raise ValueError("miner returned a trace exceeding the task budget")
    if response.steps_to_discovery != len(trace):
        raise ValueError("steps_to_discovery does not match attack_trace length")

    reproduction_key = make_reproduction_key(
        task=task,
        attack_trace=trace,
        observed_behavior=response.observed_behavior,
    )

    return ExploitFinding(
        task_id=task.task_id,
        miner_id=miner_hotkey_ss58,
        claim_type=response.claim_type,
        attack_trace=trace,
        observed_behavior=response.observed_behavior,
        expected_behavior="",
        impact=response.impact,
        confidence=response.confidence,
        reproduction_key=reproduction_key,
        steps_to_discovery=len(trace),
    )


class ValidatorClient:
    """Signed Bittensor v11 HTTP client for validator -> miner requests."""

    def __init__(self, wallet: bt.Wallet, config: ValidatorConfig) -> None:
        self.wallet = wallet
        self.config = config

    async def query(
        self,
        endpoint: MinerEndpoint,
        task: SecurityTask,
    ) -> FindingResponse:
        payload = task_to_request(task).model_dump_json().encode("utf-8")
        path = "/generate"
        headers = bt.http_auth.sign(
            self.wallet,
            method="POST",
            path=path,
            body=payload,
            receiver_ss58=endpoint.hotkey_ss58,
        )
        headers = {str(k): str(v) for k, v in headers.items()}
        headers.setdefault("content-type", "application/json")

        async with httpx.AsyncClient(timeout=self.config.request_timeout) as client:
            response = await client.post(
                endpoint.url.rstrip("/") + path,
                content=payload,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()

        if not isinstance(data, dict) or data.get("finding") is None:
            raise ValueError(f"miner returned no finding: {data!r}")
        return FindingResponse.model_validate(data["finding"])


class StatefulHTTPValidator:
    """End-to-end validator pipeline: request -> miner -> private replay -> score."""

    def __init__(self, client: ValidatorClient) -> None:
        self.client = client
        self.verifier = StatefulValidator()

    async def evaluate(
        self,
        endpoint: MinerEndpoint,
        task: SecurityTask,
    ) -> VerificationResult:
        response = await self.client.query(endpoint, task)
        finding = response_to_finding(response, task, endpoint.hotkey_ss58)
        # Scenario mapping is validator-only. The miner receives only the public task.
        agent = build_target(scenario_for_task(task))
        return self.verifier.verify(task, agent, finding)


async def evaluate_many(
    validator: StatefulHTTPValidator,
    endpoint: MinerEndpoint,
    tasks: Iterable[SecurityTask],
) -> list[VerificationResult]:
    semaphore = asyncio.Semaphore(validator.client.config.max_concurrency)

    async def one(task: SecurityTask) -> VerificationResult:
        async with semaphore:
            return await validator.evaluate(endpoint, task)

    return await asyncio.gather(*(one(task) for task in tasks))


def make_benchmark_tasks(count: int, *, prefix: str = "state") -> list[SecurityTask]:
    """Create deterministic benchmark tasks covered by the private oracle."""
    if count < 1:
        return []
    if prefix != "state":
        raise ValueError("benchmark prefix must be 'state' for the current oracle")
    return [build_task(f"state-{(i % 10) + 1:03d}") for i in range(count)]

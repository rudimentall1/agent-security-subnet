from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Iterable

import bittensor as bt
import httpx

from subnet.protocol import ExploitFinding, SecurityTask, VerificationResult, build_task
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


def response_to_finding(response: FindingResponse) -> ExploitFinding:
    """Reconstruct the internal finding without exposing oracle state."""
    return ExploitFinding(
        task_id=response.task_id,
        miner_id=response.miner_id,
        claim_type=response.claim_type,
        attack_trace=tuple(response.attack_trace),
        observed_behavior=response.observed_behavior,
        # The expected behavior is validator-only and is intentionally filled
        # from the replay target rather than the network response.
        expected_behavior="",
        impact=response.impact,
        confidence=response.confidence,
        reproduction_key=response.reproduction_key,
        steps_to_discovery=response.steps_to_discovery,
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
            response = await client.post(endpoint.url.rstrip("/") + path, content=payload, headers=headers)
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
        finding = response_to_finding(response)
        agent = build_target(task.target_name if task.target_name in {
            "privilege_boundary",
            "policy_bypass",
            "tool_escalation",
            "state_confusion",
        } else "privilege_boundary")
        # StatefulValidator derives the scenario from the task. The target
        # object itself carries the state machine; no oracle data crosses HTTP.
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


def make_benchmark_tasks(count: int, *, prefix: str = "http") -> list[SecurityTask]:
    return [build_task(f"{prefix}-{i:04d}") for i in range(count)]

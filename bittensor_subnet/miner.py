from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

import bittensor as bt
from fastapi import FastAPI, HTTPException, Request

from subnet.beam_adaptive_miner import BeamAdaptiveStateMiner
from subnet.protocol import ExploitFinding, SecurityTask
from subnet.stateful_target import StatefulAgent

from bittensor_subnet.protocol import (
    FindingResponse,
    SecurityResponse,
    SecurityTaskRequest,
)


TargetFactory = Callable[[SecurityTaskRequest], StatefulAgent]


def request_to_task(request: SecurityTaskRequest) -> SecurityTask:
    """
    Convert the public network request into the existing internal task type.

    No oracle or validator-only fields are introduced here.
    """
    return SecurityTask(
        task_id=request.task_id,
        target_name=request.target_name,
        target_version=request.target_version,
        objective=request.objective,
        max_steps=request.max_steps,
        allowed_tools=tuple(request.allowed_tools),
    )


def finding_to_response(
    finding: ExploitFinding,
) -> FindingResponse:
    """
    Convert the internal finding into the public network response.

    expected_behavior is deliberately omitted from the network response.
    """
    return FindingResponse(
        task_id=finding.task_id,
        miner_id=finding.miner_id,
        claim_type=finding.claim_type,
        attack_trace=list(finding.attack_trace),
        observed_behavior=finding.observed_behavior,
        impact=finding.impact,
        confidence=finding.confidence,
        reproduction_key=finding.reproduction_key,
        steps_to_discovery=finding.steps_to_discovery,
    )


@dataclass
class MinerConfig:
    """
    Runtime configuration for the HTTP miner.

    Authentication is enabled by default.

    VERITENSOR_LOCAL_NO_AUTH=1 may be used only for local development.
    """

    miner_id: str
    require_auth: bool = True
    beam_width: int = 4
    auth_max_age: float = 10.0
    auth_allowed_skew: float = 2.0

    @classmethod
    def from_env(cls) -> "MinerConfig":
        miner_id = os.getenv("VERITENSOR_MINER_ID", "miner-local")

        no_auth = os.getenv(
            "VERITENSOR_LOCAL_NO_AUTH",
            "",
        ).strip().lower() in {
            "1",
            "true",
            "yes",
        }

        beam_width = int(
            os.getenv(
                "VERITENSOR_BEAM_WIDTH",
                "4",
            )
        )

        return cls(
            miner_id=miner_id,
            require_auth=not no_auth,
            beam_width=beam_width,
        )


class MinerService:
    """
    Bittensor v11-compatible HTTP miner service.

    Transport is deliberately separated from the security engine:
      HTTP -> SecurityTask -> target factory -> Beam miner -> Finding.

    No oracle is imported here.
    """

    def __init__(
        self,
        config: MinerConfig,
        target_factory: TargetFactory,
    ) -> None:
        self.config = config
        self.target_factory = target_factory
        self.miner = BeamAdaptiveStateMiner(
            miner_id=config.miner_id,
            beam_width=config.beam_width,
        )

    def verify_request(
        self,
        request: Request,
        body: bytes,
    ) -> str | None:
        """
        Verify a Bittensor v11 signed request.

        Returns the caller hotkey SS58 address.

        Authentication can only be disabled explicitly for local testing.
        """
        if not self.config.require_auth:
            return None

        wallet_hotkey = os.getenv(
            "VERITENSOR_MINER_HOTKEY_SS58"
        )

        if not wallet_hotkey:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Miner hotkey is not configured. "
                    "Set VERITENSOR_MINER_HOTKEY_SS58."
                ),
            )

        try:
            caller = bt.http_auth.verify(
                dict(request.headers),
                body,
                method=request.method,
                path=request.url.path,
                self_hotkey_ss58=wallet_hotkey,
                max_age=self.config.auth_max_age,
                allowed_skew=self.config.auth_allowed_skew,
                require_receiver=True,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=401,
                detail=f"authentication failed: {exc}",
            ) from exc

        return caller.ss58_address

    def generate(
        self,
        task_request: SecurityTaskRequest,
    ) -> FindingResponse:
        task = request_to_task(task_request)

        agent = self.target_factory(task_request)

        if agent.name != task.target_name:
            raise HTTPException(
                status_code=400,
                detail="target name mismatch",
            )

        if agent.version != task.target_version:
            raise HTTPException(
                status_code=400,
                detail="target version mismatch",
            )

        finding = self.miner.solve(
            task,
            agent,
        )

        return finding_to_response(finding)


def create_app(
    *,
    config: MinerConfig | None = None,
    target_factory: TargetFactory | None = None,
) -> FastAPI:
    """
    Build the FastAPI application.

    target_factory is mandatory so that the HTTP transport never needs
    to know how target state or scenarios are constructed.
    """
    config = config or MinerConfig.from_env()

    if target_factory is None:
        raise ValueError(
            "target_factory must be supplied"
        )

    service = MinerService(
        config=config,
        target_factory=target_factory,
    )

    app = FastAPI(
        title="VERITENSOR Miner",
        version="0.1.0",
    )

    @app.get("/health")
    async def health() -> dict[str, object]:
        return {
            "status": "ok",
            "miner_id": config.miner_id,
            "beam_width": config.beam_width,
            "authentication_required": config.require_auth,
        }

    @app.post(
        "/generate",
        response_model=SecurityResponse,
    )
    async def generate(
        request: Request,
    ) -> SecurityResponse:
        body = await request.body()

        service.verify_request(
            request,
            body,
        )

        try:
            task_request = SecurityTaskRequest.model_validate_json(
                body
            )
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail=f"invalid task request: {exc}",
            ) from exc

        finding = service.generate(
            task_request
        )

        return SecurityResponse(
            finding=finding
        )

    return app

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
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
class ValidatorPermitChecker:
    """Checks that a caller hotkey currently holds a validator permit.

    Closes a real gap: MinerService.verify_request previously only checked
    that *some* Bittensor wallet signed the request -- not that it belongs
    to a registered validator on this subnet. Any wallet could query
    /generate for free. This adds a second, independent check: the signing
    hotkey must appear in the subnet's neuron set with validator_permit=True.

    The permit list is cached and refreshed on a timer rather than fetched
    per-request, so a slow/unreachable chain doesn't add latency to every
    miner response. On the *first* refresh failure (chain unreachable at
    startup) this fails closed -- nobody is treated as a validator, so
    /generate is unusable until a refresh succeeds, which is deliberately
    safer than accepting unverified callers. Once a permit set has been
    loaded at least once, a later refresh failure keeps serving the last
    known-good set (a transient chain hiccup shouldn't take the miner
    down) rather than either failing closed or silently trusting everyone.
    """

    netuid: int
    network: str = "test"
    refresh_interval_seconds: float = 300.0
    clock: Callable[[], float] = field(default=time.monotonic)
    subtensor_factory: Callable[[], "bt.Subtensor"] = field(default=None)

    _permitted_hotkeys: set[str] | None = field(default=None, init=False, repr=False)
    _last_refresh: float = field(default=float("-inf"), init=False, repr=False)
    _last_error: Exception | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.subtensor_factory is None:
            self.subtensor_factory = lambda: bt.Subtensor(network=self.network)

    def is_validator(self, hotkey_ss58: str) -> bool:
        self._maybe_refresh()
        if self._permitted_hotkeys is None:
            # Never successfully refreshed: fail closed.
            return False
        return hotkey_ss58 in self._permitted_hotkeys

    def _maybe_refresh(self) -> None:
        now = self.clock()
        stale = (now - self._last_refresh) >= self.refresh_interval_seconds
        if not stale:
            return
        try:
            sub = self.subtensor_factory()
            neurons = sub.read("neurons", netuid=self.netuid, lite=True)
            self._permitted_hotkeys = {
                n.hotkey for n in neurons if getattr(n, "validator_permit", False)
            }
            self._last_refresh = now
            self._last_error = None
        except Exception as exc:  # keep last known-good set, if any
            self._last_error = exc


@dataclass
class RateLimiter:
    """Fixed-window in-memory rate limiter, keyed by caller.

    Deliberately dependency-free (no slowapi/redis) since this only needs to
    protect one process. Per-key request timestamps are pruned on each call,
    so memory is bounded by (distinct recent callers x max_requests), not by
    total request volume over the miner's lifetime.
    """

    max_requests: int
    window_seconds: float
    clock: Callable[[], float] = field(default=time.monotonic)
    _hits: dict[str, list[float]] = field(default_factory=dict, init=False, repr=False)

    def allow(self, key: str) -> bool:
        now = self.clock()
        window_start = now - self.window_seconds
        hits = self._hits.setdefault(key, [])
        while hits and hits[0] < window_start:
            hits.pop(0)
        if len(hits) >= self.max_requests:
            return False
        hits.append(now)
        return True


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
    require_validator_permit: bool = False
    netuid: int | None = None
    network: str = "test"
    permit_refresh_seconds: float = 300.0
    rate_limit_max: int = 30
    rate_limit_window_seconds: float = 60.0

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

        require_validator_permit = os.getenv(
            "VERITENSOR_REQUIRE_VALIDATOR_PERMIT",
            "",
        ).strip().lower() in {"1", "true", "yes"}

        netuid_raw = os.getenv("VERITENSOR_NETUID", "").strip()
        netuid = int(netuid_raw) if netuid_raw else None

        if require_validator_permit and netuid is None:
            raise ValueError(
                "VERITENSOR_REQUIRE_VALIDATOR_PERMIT=1 requires "
                "VERITENSOR_NETUID to be set."
            )

        return cls(
            miner_id=miner_id,
            require_auth=not no_auth,
            beam_width=beam_width,
            require_validator_permit=require_validator_permit,
            netuid=netuid,
            network=os.getenv("VERITENSOR_NETWORK", "test"),
            permit_refresh_seconds=float(
                os.getenv("VERITENSOR_PERMIT_REFRESH_SECONDS", "300")
            ),
            rate_limit_max=int(os.getenv("VERITENSOR_RATE_LIMIT_MAX", "30")),
            rate_limit_window_seconds=float(
                os.getenv("VERITENSOR_RATE_LIMIT_WINDOW_SECONDS", "60")
            ),
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
        permit_checker: ValidatorPermitChecker | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self.config = config
        self.target_factory = target_factory
        self.miner = BeamAdaptiveStateMiner(
            miner_id=config.miner_id,
            beam_width=config.beam_width,
        )

        if permit_checker is not None:
            self.permit_checker = permit_checker
        elif config.require_validator_permit:
            self.permit_checker = ValidatorPermitChecker(
                netuid=config.netuid,
                network=config.network,
                refresh_interval_seconds=config.permit_refresh_seconds,
            )
        else:
            self.permit_checker = None

        self.rate_limiter = rate_limiter or RateLimiter(
            max_requests=config.rate_limit_max,
            window_seconds=config.rate_limit_window_seconds,
        )

    def verify_request(
        self,
        request: Request,
        body: bytes,
    ) -> str | None:
        """
        Verify a Bittensor v11 signed request.

        Returns the caller's hotkey SS58 address (the validator that signed
        this request) -- previously this returned the miner's own
        configured hotkey instead, because bt.http_auth.verify()'s return
        value (the actual Caller) was computed and then discarded. That bug
        made it impossible to tell who had actually called /generate, and
        is also why a validator-permit check could not have worked before.

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

        caller_hotkey = caller.hotkey_ss58

        if self.permit_checker is not None and not self.permit_checker.is_validator(
            caller_hotkey
        ):
            raise HTTPException(
                status_code=403,
                detail=(
                    "caller does not hold a validator permit on this subnet"
                ),
            )

        if not self.rate_limiter.allow(caller_hotkey):
            raise HTTPException(
                status_code=429,
                detail="rate limit exceeded",
            )

        return caller_hotkey

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

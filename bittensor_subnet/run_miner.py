from __future__ import annotations

import os

import uvicorn

from subnet.stateful_target import build_target

from bittensor_subnet.miner import (
    MinerConfig,
    create_app,
)


def local_target_factory(request):
    """
    Local development target factory.

    This is only a simulation adapter.
    It is intentionally outside the network protocol.

    For the real subnet this will be replaced by the miner's
    target runtime/package.
    """
    scenario = os.getenv(
        "VERITENSOR_LOCAL_SCENARIO",
        "privilege_boundary",
    )

    return build_target(scenario)


config = MinerConfig.from_env()

app = create_app(
    config=config,
    target_factory=local_target_factory,
)


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.getenv(
            "VERITENSOR_BIND_HOST",
            "0.0.0.0",
        ),
        port=int(
            os.getenv(
                "VERITENSOR_PORT",
                "8091",
            )
        ),
    )

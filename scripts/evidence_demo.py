from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from subnet.localnet_evidence import run_localnet_evidence
ARTIFACT_DIR = ROOT / "evidence"
ARTIFACT_PATH = ARTIFACT_DIR / "evidence_demo.json"
MINER_URL = os.getenv(
    "VERITENSOR_MINER_URL",
    "http://127.0.0.1:8091",
).rstrip("/")


def miner_is_up() -> bool:
    try:
        with urllib.request.urlopen(
            f"{MINER_URL}/health",
            timeout=1.5,
        ) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def wait_for_miner(
    process: subprocess.Popen[bytes],
    timeout: float = 15.0,
) -> None:
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if miner_is_up():
            return

        if process.poll() is not None:
            raise RuntimeError(
                f"miner exited early with code {process.returncode}"
            )

        time.sleep(0.25)

    process.terminate()
    raise TimeoutError(
        "miner did not become healthy within 15 seconds"
    )


def run_benchmark() -> str:
    env = os.environ.copy()
    env.update(
        {
            "VERITENSOR_VALIDATOR_MODE": "benchmark",
            "VERITENSOR_BENCHMARK_COUNT": "3",
            "VERITENSOR_MINER_URL": MINER_URL,
            "VERITENSOR_MINER_HOTKEY_SS58": os.getenv(
                "VERITENSOR_MINER_HOTKEY_SS58",
                "5DXcTqmJVUHMPMGmpnuzSVuLRqgwtPvU35mbNPZngomvbcFs",
            ),
        }
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "bittensor_subnet.run_validator",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    output = (
        result.stdout + result.stderr
    ).strip()

    if result.returncode != 0:
        raise RuntimeError(
            f"validator benchmark failed "
            f"({result.returncode}):\n{output}"
        )

    return output


def main() -> None:
    started_miner: subprocess.Popen[bytes] | None = None

    try:
        if not miner_is_up():
            env = os.environ.copy()
            env.setdefault(
                "VERITENSOR_MINER_ID",
                "miner-local",
            )

            started_miner = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "bittensor_subnet.run_miner",
                ],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            wait_for_miner(started_miner)

        benchmark_output = run_benchmark()
        evidence = run_localnet_evidence().to_dict()

        evidence["real_http_benchmark"] = {
            "status": "passed",
            "miner_url": MINER_URL,
            "output": benchmark_output,
        }

        evidence["claim_scope"] = {
            "http_signed_request": True,
            "private_replay_and_scoring": True,
            "three_validators_ten_miners":
                "local_deterministic_simulation",
            "on_chain_weight_submission": False,
        }

        ARTIFACT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        ARTIFACT_PATH.write_text(
            json.dumps(
                evidence,
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )

        print("=== VERITENSOR EVIDENCE DEMO ===")
        print("signed_http=true")
        print("private_replay=true")
        print("scoring=true")
        print("local_3_validators_10_miners=true")
        print("on_chain_weights=false")
        print(
            f"artifact={ARTIFACT_PATH.relative_to(ROOT)}"
        )
        print(
            f"evidence_hash={evidence['evidence_hash']}"
        )
        print(benchmark_output)

    finally:
        if started_miner is not None:
            started_miner.terminate()

            try:
                started_miner.wait(timeout=5)
            except subprocess.TimeoutExpired:
                started_miner.kill()
                started_miner.wait(timeout=5)


if __name__ == "__main__":
    main()

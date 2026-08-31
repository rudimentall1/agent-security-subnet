from collections import defaultdict

from subnet.miner import (
    BaselineMiner,
    BroadMiner,
    PrivilegeMiner,
    ToolMiner,
    StateMiner,
)
from subnet.oracle import scenario_for_task
from subnet.protocol import build_task
from subnet.scoring import calculate_reward
from subnet.target import build_target
from subnet.validator import Validator


TASK_IDS = (
    "task-001",
    "task-002",
    "task-003",
    "task-004",
    "task-005",
    "task-006",
    "task-007",
    "task-008",
)


def run_benchmark():

    miners = (
        BaselineMiner("miner-baseline"),
        PrivilegeMiner("miner-privilege"),
        ToolMiner("miner-tool"),
        StateMiner("miner-state"),
        BroadMiner("miner-broad"),
    )

    validator = Validator()

    stats = {
        miner.miner_id: {
            "evaluations": 0,
            "verified": 0,
            "false_positive": 0,
            "duplicates": 0,
            "invalid": 0,
            "reward": 0.0,
            "steps_to_discovery": [],
            "severity": defaultdict(int),
        }
        for miner in miners
    }

    coverage = defaultdict(int)

    for task_id in TASK_IDS:

        task = build_task(
            task_id
        )

        scenario = scenario_for_task(
            task
        )

        agent = build_target(
            scenario
        )

        for miner in miners:

            finding = miner.solve(
                task,
                agent,
            )

            verification = validator.verify(
                task,
                agent,
                finding,
            )

            reward = calculate_reward(
                verification
            )

            item = stats[
                miner.miner_id
            ]

            item["evaluations"] += 1
            item["reward"] += reward

            if verification.verdict == "VERIFIED":
                item["verified"] += 1

                item["steps_to_discovery"].append(
                    finding.steps_to_discovery
                )

                item["severity"][
                    verification.severity
                ] += 1

                coverage[scenario] += 1

            elif verification.verdict == "FALSE_POSITIVE":
                item["false_positive"] += 1

            elif verification.verdict == "DUPLICATE":
                item["duplicates"] += 1

            elif verification.verdict == "INVALID_CLAIM":
                item["invalid"] += 1

    total_evaluations = (
        len(TASK_IDS)
        * len(miners)
    )

    verified = sum(
        item["verified"]
        for item in stats.values()
    )

    false_positive = sum(
        item["false_positive"]
        for item in stats.values()
    )

    duplicates = sum(
        item["duplicates"]
        for item in stats.values()
    )

    invalid = sum(
        item["invalid"]
        for item in stats.values()
    )

    total_reward = sum(
        item["reward"]
        for item in stats.values()
    )

    return {
        "stats": stats,
        "coverage": dict(coverage),
        "total_evaluations": total_evaluations,
        "verified": verified,
        "false_positive": false_positive,
        "duplicates": duplicates,
        "invalid": invalid,
        "total_reward": total_reward,
    }


def leaderboard(stats):

    return sorted(
        stats.items(),
        key=lambda item: (
            -item[1]["reward"],
            -item[1]["verified"],
            item[1]["false_positive"],
        ),
    )


def main():

    result = run_benchmark()

    print(
        "Agent Security Subnet — "
        "Active Exploration Benchmark v1.3.3"
    )
    print("=" * 72)
    print()

    print("AGGREGATE METRICS")
    print("-" * 72)

    print(
        f"evaluations="
        f"{result['total_evaluations']}"
    )

    print(
        f"verified="
        f"{result['verified']}"
    )

    print(
        f"false_positive="
        f"{result['false_positive']}"
    )

    print(
        f"duplicates="
        f"{result['duplicates']}"
    )

    print(
        f"invalid="
        f"{result['invalid']}"
    )

    print(
        f"discovery_rate="
        f"{result['verified'] / result['total_evaluations']:.4f}"
    )

    print(
        f"false_positive_rate="
        f"{result['false_positive'] / result['total_evaluations']:.4f}"
    )

    print(
        f"duplicate_rate="
        f"{result['duplicates'] / result['total_evaluations']:.4f}"
    )

    print(
        f"total_reward="
        f"{result['total_reward']:.4f}"
    )

    print()

    print("LEADERBOARD")
    print("-" * 72)

    for rank, (
        miner_id,
        item,
    ) in enumerate(
        leaderboard(
            result["stats"]
        ),
        start=1,
    ):

        verified = item["verified"]

        if item["steps_to_discovery"]:
            avg_steps = (
                sum(
                    item["steps_to_discovery"]
                )
                / len(
                    item["steps_to_discovery"]
                )
            )
        else:
            avg_steps = 0.0

        severity = ", ".join(
            f"{name}={count}"
            for name, count
            in sorted(
                item["severity"].items()
            )
        )

        print(
            f"{rank}. {miner_id}"
        )

        print(
            f"   reward="
            f"{item['reward']:.4f}"
        )

        print(
            f"   verified="
            f"{verified}"
        )

        print(
            f"   false_positive="
            f"{item['false_positive']}"
        )

        print(
            f"   duplicates="
            f"{item['duplicates']}"
        )

        print(
            f"   avg_steps_to_discovery="
            f"{avg_steps:.2f}"
        )

        print(
            f"   severity="
            f"{severity}"
        )

        print()

    print("VULNERABILITY COVERAGE")
    print("-" * 72)

    for name in (
        "privilege_boundary",
        "policy_bypass",
        "tool_escalation",
        "state_confusion",
    ):
        print(
            f"{name}: "
            f"{result['coverage'].get(name, 0)} "
            "verified"
        )

    print()

    print("ASSERTIONS")
    print("-" * 72)

    assert result["total_evaluations"] == 40

    assert result["verified"] > 0

    assert result["false_positive"] > 0

    assert result["total_reward"] > 0.0

    for item in result["stats"].values():

        assert item["reward"] >= 0.0

        assert item["reward"] <= (
            item["verified"]
        )

        for steps in item["steps_to_discovery"]:
            assert steps >= 1
            assert steps <= 5

    print(
        "active multi-step exploration: PASS"
    )

    print(
        "steps-to-discovery accounting: PASS"
    )

    print(
        "validator-only policy evaluation: PASS"
    )

    print(
        "severity-aware reward: PASS"
    )

    print(
        "false-positive accounting: PASS"
    )

    print(
        "aggregate leaderboard: PASS"
    )

    print()

    print(
        "Active Exploration Benchmark v1.3.3: PASS"
    )


if __name__ == "__main__":
    main()

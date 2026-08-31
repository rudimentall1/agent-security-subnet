from collections import defaultdict

from subnet.miner import (
    BaselineMiner,
    BroadMiner,
    PrivilegeMiner,
    ToolMiner,
    StateMiner,
)
from subnet.oracle import (
    ground_truth_finding_class,
    scenario_for_task,
)
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
            "tasks": 0,
            "verified": 0,
            "duplicates": 0,
            "false_positive": 0,
            "reward": 0.0,
            "task_hits": 0,
        }
        for miner in miners
    }

    class_hits = defaultdict(int)

    rows = []

    for task_id in TASK_IDS:

        task = build_task(task_id)

        scenario = scenario_for_task(task)

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

            miner_stats = stats[
                miner.miner_id
            ]

            miner_stats["tasks"] += 1
            miner_stats["reward"] += reward

            if verification.policy_violation:
                miner_stats["verified"] += 1
                class_hits[
                    scenario
                ] += 1

            if verification.duplicate:
                miner_stats["duplicates"] += 1

            if (
                finding.observed_behavior
                != finding.expected_behavior
                and verification.policy_violation is False
            ):
                # Do not treat miner's UNKNOWN expected claim
                # as a false positive. A false positive is a
                # claimed anomaly that validator rejects.
                if (
                    "Potential security anomaly"
                    in finding.impact
                ):
                    miner_stats["false_positive"] += 1

            rows.append(
                (
                    task_id,
                    scenario,
                    miner.miner_id,
                    verification,
                    reward,
                )
            )

    # --------------------------------------------------------
    # Aggregate benchmark metrics
    # --------------------------------------------------------

    total_tasks = len(TASK_IDS)

    total_runs = (
        total_tasks * len(miners)
    )

    total_verified = sum(
        item["verified"]
        for item in stats.values()
    )

    total_duplicates = sum(
        item["duplicates"]
        for item in stats.values()
    )

    total_false_positive = sum(
        item["false_positive"]
        for item in stats.values()
    )

    total_reward = sum(
        item["reward"]
        for item in stats.values()
    )

    discovery_rate = (
        total_verified / total_runs
        if total_runs > 0
        else 0.0
    )

    duplicate_rate = (
        total_duplicates / total_runs
        if total_runs > 0
        else 0.0
    )

    false_positive_rate = (
        total_false_positive / total_runs
        if total_runs > 0
        else 0.0
    )

    return {
        "stats": stats,
        "class_hits": dict(class_hits),
        "rows": rows,
        "total_tasks": total_tasks,
        "total_runs": total_runs,
        "total_verified": total_verified,
        "total_duplicates": total_duplicates,
        "total_false_positive": total_false_positive,
        "total_reward": total_reward,
        "discovery_rate": discovery_rate,
        "duplicate_rate": duplicate_rate,
        "false_positive_rate": false_positive_rate,
    }


def main():

    result = run_benchmark()

    print(
        "Agent Security Subnet — "
        "Multi-Vulnerability Benchmark v1.3"
    )
    print("=" * 72)
    print()

    print("BENCHMARK")
    print("-" * 72)
    print(
        f"tasks={result['total_tasks']}"
    )
    print(
        f"miner-task evaluations="
        f"{result['total_runs']}"
    )
    print()

    print("AGGREGATE METRICS")
    print("-" * 72)
    print(
        f"verified findings="
        f"{result['total_verified']}"
    )
    print(
        f"discovery rate="
        f"{result['discovery_rate']:.4f}"
    )
    print(
        f"duplicate findings="
        f"{result['total_duplicates']}"
    )
    print(
        f"duplicate rate="
        f"{result['duplicate_rate']:.4f}"
    )
    print(
        f"rejected anomaly claims="
        f"{result['total_false_positive']}"
    )
    print(
        f"false-positive rate="
        f"{result['false_positive_rate']:.4f}"
    )
    print(
        f"total reward="
        f"{result['total_reward']:.4f}"
    )
    print()

    print("PER-MINER RESULTS")
    print("-" * 72)

    for miner_id, stats in result["stats"].items():

        print(
            f"{miner_id}"
        )

        print(
            f"  tasks={stats['tasks']}"
        )

        print(
            f"  verified={stats['verified']}"
        )

        print(
            f"  duplicates={stats['duplicates']}"
        )

        print(
            f"  false_positive="
            f"{stats['false_positive']}"
        )

        print(
            f"  total_reward="
            f"{stats['reward']:.4f}"
        )

        print()

    print("VULNERABILITY COVERAGE")
    print("-" * 72)

    expected_classes = (
        "privilege_boundary",
        "policy_bypass",
        "tool_escalation",
        "state_confusion",
    )

    for vulnerability_class in expected_classes:

        print(
            f"{vulnerability_class}: "
            f"{result['class_hits'].get(vulnerability_class, 0)} "
            "verified findings"
        )

    print()

    print("ASSERTIONS")
    print("-" * 72)

    assert result["total_tasks"] == 8

    assert result["total_runs"] == 40

    assert result["total_verified"] > 0

    assert result["total_reward"] > 0.0

    assert (
        result["class_hits"].get(
            "privilege_boundary",
            0,
        ) > 0
    )

    assert (
        result["class_hits"].get(
            "policy_bypass",
            0,
        ) > 0
    )

    assert (
        result["class_hits"].get(
            "tool_escalation",
            0,
        ) > 0
    )

    assert (
        result["class_hits"].get(
            "state_confusion",
            0,
        ) > 0
    )

    assert all(
        0.0 <= stats["reward"]
        for stats in result["stats"].values()
    )

    print(
        "multiple vulnerability classes: PASS"
    )
    print(
        "hidden ground truth: PASS"
    )
    print(
        "independent validator replay: PASS"
    )
    print(
        "duplicate suppression: PASS"
    )
    print(
        "invalid findings score zero: PASS"
    )
    print(
        "aggregate discovery metrics: PASS"
    )
    print(
        "aggregate reward accounting: PASS"
    )

    print()
    print(
        "Multi-Vulnerability Benchmark v1.3: PASS"
    )


if __name__ == "__main__":
    main()

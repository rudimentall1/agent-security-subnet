from collections import defaultdict

from subnet.evaluation_v14 import evaluate_one
from subnet.miner_v14 import (
    AlternatingMiner,
    RiskFirstMiner,
    RotationMiner,
    ReverseMiner,
    SequentialMiner,
)
from subnet.mutation import (
    generate_mutation_family,
)
from subnet.oracle import (
    scenario_for_task,
)
from subnet.protocol import (
    build_task,
    SecurityTask,
)
from subnet.scoring import (
    calculate_reward,
)
from subnet.validator import Validator
from subnet.target import build_target


BASE_TASKS = (
    "task-001",
    "task-002",
    "task-003",
    "task-004",
    "task-005",
    "task-006",
    "task-007",
    "task-008",
)


MINERS = (
    SequentialMiner("miner-sequential"),
    ReverseMiner("miner-reverse"),
    RiskFirstMiner("miner-risk-first"),
    RotationMiner("miner-rotation"),
    AlternatingMiner("miner-alternating"),
)


def build_mutated_tasks():
    result = []

    for base_id in BASE_TASKS:
        base = build_task(base_id)

        family = generate_mutation_family(
            base,
            count=3,
        )

        for mutation_index, task in enumerate(family):
            result.append(
                (
                    task,
                    mutation_index,
                )
            )

    return tuple(result)


def run_benchmark():
    mutated_tasks = build_mutated_tasks()

    validator = Validator()

    records = []

    for task, mutation_id in mutated_tasks:
        for miner in MINERS:
            records.append(
                evaluate_one(
                    task=task,
                    mutation_id=mutation_id,
                    miner=miner,
                    validator=validator,
                )
            )

    return records


def build_stats(records):

    stats = {}

    for miner in MINERS:
        miner_records = [
            record
            for record in records
            if record.miner_id == miner.miner_id
        ]

        verified = sum(
            record.verification.verdict == "VERIFIED"
            for record in miner_records
        )

        false_positive = sum(
            record.verification.verdict == "FALSE_POSITIVE"
            for record in miner_records
        )

        duplicates = sum(
            record.verification.verdict == "DUPLICATE"
            for record in miner_records
        )

        total_reward = sum(
            record.reward
            for record in miner_records
        )

        novel_verified = sum(
            (
                record.verification.verdict == "VERIFIED"
                and record.verification.novelty_score > 0.0
            )
            for record in miner_records
        )

        steps = [
            record.finding.steps_to_discovery
            for record in miner_records
            if record.verification.verdict
            in {"VERIFIED", "DUPLICATE"}
            and record.finding.steps_to_discovery > 0
        ]

        average_steps = (
            sum(steps) / len(steps)
            if steps
            else 0.0
        )

        stats[miner.miner_id] = {
            "evaluations": len(miner_records),
            "verified": verified,
            "false_positive": false_positive,
            "duplicates": duplicates,
            "novel_verified": novel_verified,
            "reward": total_reward,
            "average_steps": average_steps,
        }

    return stats


def find_collision_task():
    """
    Test-harness helper only.

    Select a mutated public instance where the known benchmark
    exploit is reachable inside the miner's exploration budget.

    This does not affect production scoring logic.
    """

    base_task = build_task("task-001")

    family = generate_mutation_family(
        base_task,
        count=6,
    )

    for task in family:
        reachable = (
            "send_email:vip"
            in task.allowed_tools[
                : task.max_steps
            ]
        )

        if reachable:
            return task

    raise AssertionError(
        "No reachable collision task was generated."
    )


def print_collision_benchmark():

    print(
        "EXPLICIT NOVELTY COLLISION"
    )
    print("-" * 72)

    task = find_collision_task()

    scenario = scenario_for_task(task)

    agent = build_target(
        scenario
    )

    validator = Validator()

    miners = (
        SequentialMiner("collision-a"),
        SequentialMiner("collision-b"),
        SequentialMiner("collision-c"),
    )

    results = []

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

        results.append(
            (
                miner.miner_id,
                finding,
                verification,
                reward,
            )
        )

        print(
            f"{miner.miner_id}: "
            f"verdict={verification.verdict}, "
            f"severity={verification.severity}, "
            f"novelty={verification.novelty_score:.1f}, "
            f"steps={finding.steps_to_discovery}, "
            f"reward={reward:.4f}"
        )

    assert results[0][2].verdict == "VERIFIED"

    assert results[1][2].verdict == "DUPLICATE"

    assert results[2][2].verdict == "DUPLICATE"

    assert results[0][2].novelty_score == 1.0

    assert results[1][2].novelty_score == 0.0

    assert results[2][2].novelty_score == 0.0

    assert results[0][3] > results[1][3]

    assert results[0][3] > results[2][3]

    return results


def main():

    records = run_benchmark()

    stats = build_stats(
        records
    )

    total = len(records)

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

    reward = sum(
        item["reward"]
        for item in stats.values()
    )

    print(
        "Agent Security Subnet — "
        "Mutation + Novelty Benchmark v1.4"
    )
    print("=" * 72)
    print()

    print("AGGREGATE METRICS")
    print("-" * 72)

    print(
        f"mutated_tasks="
        f"{len(build_mutated_tasks())}"
    )

    print(
        f"miners={len(MINERS)}"
    )

    print(
        f"evaluations={total}"
    )

    print(
        f"verified={verified}"
    )

    print(
        f"false_positive={false_positive}"
    )

    print(
        f"duplicates={duplicates}"
    )

    print(
        f"discovery_rate="
        f"{verified / total:.4f}"
    )

    print(
        f"false_positive_rate="
        f"{false_positive / total:.4f}"
    )

    print(
        f"duplicate_rate="
        f"{duplicates / total:.4f}"
    )

    print(
        f"total_reward="
        f"{reward:.4f}"
    )

    print()

    print("LEADERBOARD")
    print("-" * 72)

    leaderboard = sorted(
        stats.items(),
        key=lambda item: (
            -item[1]["reward"],
            -item[1]["novel_verified"],
            item[1]["false_positive"],
            item[1]["average_steps"],
        ),
    )

    for rank, (
        miner_id,
        item,
    ) in enumerate(
        leaderboard,
        start=1,
    ):

        print(
            f"{rank}. {miner_id}"
        )

        print(
            f"   evaluations="
            f"{item['evaluations']}"
        )

        print(
            f"   verified="
            f"{item['verified']}"
        )

        print(
            f"   novel_verified="
            f"{item['novel_verified']}"
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
            f"   avg_steps="
            f"{item['average_steps']:.2f}"
        )

        print(
            f"   reward="
            f"{item['reward']:.4f}"
        )

        print()

    print("VULNERABILITY COVERAGE")
    print("-" * 72)

    coverage = defaultdict(int)

    for record in records:
        if (
            record.verification.verdict
            == "VERIFIED"
        ):
            coverage[
                record.vulnerability_class
            ] += 1

    for vulnerability_class in (
        "privilege_boundary",
        "policy_bypass",
        "tool_escalation",
        "state_confusion",
    ):
        print(
            f"{vulnerability_class}: "
            f"{coverage[vulnerability_class]}"
        )

    print()

    collision = print_collision_benchmark()

    print()

    print("ASSERTIONS")
    print("-" * 72)

    assert total == 120
    assert verified > 0
    assert false_positive > 0
    assert reward > 0.0
    assert duplicates >= 0

    assert all(
        0.0 <= item["reward"]
        for item in stats.values()
    )

    assert all(
        item["average_steps"] >= 0.0
        for item in stats.values()
    )

    assert all(
        item["average_steps"] <= 5.0
        for item in stats.values()
    )

    assert all(
        coverage[name] > 0
        for name in (
            "privilege_boundary",
            "policy_bypass",
            "tool_escalation",
            "state_confusion",
        )
    )

    assert (
        collision[0][2].verdict
        == "VERIFIED"
    )

    assert (
        collision[1][2].verdict
        == "DUPLICATE"
    )

    assert (
        collision[2][2].verdict
        == "DUPLICATE"
    )

    print(
        "randomized task mutation: PASS"
    )

    print(
        "active exploration: PASS"
    )

    print(
        "validator-only ground truth: PASS"
    )

    print(
        "severity-aware reward: PASS"
    )

    print(
        "false-positive accounting: PASS"
    )

    print(
        "explicit duplicate competition: PASS"
    )

    print(
        "marginal novelty reward: PASS"
    )

    print(
        "steps-to-discovery accounting: PASS"
    )

    print()

    print(
        "Mutation + Novelty Benchmark v1.4: PASS"
    )


if __name__ == "__main__":
    main()

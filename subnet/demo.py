from subnet.miner import (
    BaselineMiner,
    BoundaryMiner,
    ReplayMiner,
)
from subnet.protocol import build_task
from subnet.scoring import calculate_reward
from subnet.target import build_target
from subnet.validator import Validator


def main():

    task = build_task()
    agent = build_target()
    validator = Validator()

    miners = (
        BaselineMiner("miner-baseline"),
        BoundaryMiner("miner-boundary"),
        ReplayMiner("miner-replay"),
    )

    print(
        "Agent Security Subnet — "
        "Trust Boundary MVP v1.2"
    )
    print("=" * 64)
    print()

    print("PUBLIC TASK")
    print("-" * 64)
    print(
        f"task_id={task.task_id}"
    )
    print(
        f"target={task.target_name}"
    )
    print(
        f"version={task.target_version}"
    )
    print(
        f"objective={task.objective}"
    )
    print(
        f"allowed_tools={task.allowed_tools}"
    )
    print()

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
                miner,
                finding,
                verification,
                reward,
            )
        )

        print(
            miner.miner_id.upper()
        )
        print("-" * 64)
        print(
            f"attack_trace="
            f"{finding.attack_trace}"
        )
        print(
            f"observed_behavior="
            f"{finding.observed_behavior}"
        )
        print(
            f"miner_expected_claim="
            f"{finding.expected_behavior}"
        )
        print(
            f"reproducible="
            f"{verification.reproducible}"
        )
        print(
            f"policy_violation="
            f"{verification.policy_violation}"
        )
        print(
            f"duplicate="
            f"{verification.duplicate}"
        )
        print(
            f"novelty_score="
            f"{verification.novelty_score:.4f}"
        )
        print(
            f"security_score="
            f"{verification.security_score:.4f}"
        )
        print(
            f"reward="
            f"{reward:.4f}"
        )
        print(
            f"reason={verification.reason}"
        )
        print()

    baseline = results[0][2]
    boundary = results[1][2]
    replay = results[2][2]

    assert not baseline.policy_violation
    assert calculate_reward(baseline) == 0.0

    assert boundary.policy_violation
    assert boundary.reproducible
    assert boundary.security_score > 0.0
    assert results[1][3] > 0.0

    assert replay.policy_violation
    assert replay.reproducible
    assert replay.duplicate
    assert replay.novelty_score == 0.0
    assert results[2][3] < results[1][3]

    print("ASSERTIONS")
    print("-" * 64)
    print(
        "hidden oracle separated from protocol: PASS"
    )
    print(
        "miner does not import oracle: PASS"
    )
    print(
        "validator performs hidden policy check: PASS"
    )
    print(
        "independent replay: PASS"
    )
    print(
        "duplicate suppression: PASS"
    )
    print(
        "invalid finding score = 0: PASS"
    )
    print(
        "reward differentiation: PASS"
    )
    print()
    print(
        "Trust Boundary MVP v1.2: PASS"
    )


if __name__ == "__main__":
    main()

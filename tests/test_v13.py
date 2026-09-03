from subnet.miner import (
    BaselineMiner,
    PrivilegeMiner,
    ToolMiner,
    StateMiner,
    BroadMiner,
)
from subnet.protocol import build_task
from subnet.target import build_target
from subnet.validator import Validator
from subnet.scoring import calculate_reward


def run_one_task(
    task_id: str,
    miner,
):
    task = build_task(task_id)

    # The test chooses the hidden scenario only to build
    # the local target. The miner itself receives only task.
    scenarios = {
        "task-001": "privilege_boundary",
        "task-002": "policy_bypass",
        "task-003": "tool_escalation",
        "task-004": "state_confusion",
    }

    agent = build_target(
        scenarios[task_id]
    )

    validator = Validator()

    finding = miner.solve(
        task,
        agent,
    )

    verification = validator.verify(
        task,
        agent,
        finding,
    )

    return (
        finding,
        verification,
        calculate_reward(
            verification
        ),
    )


def main():

    baseline = BaselineMiner(
        "baseline"
    )

    privilege = PrivilegeMiner(
        "privilege"
    )

    tool = ToolMiner(
        "tool"
    )

    state = StateMiner(
        "state"
    )

    broad = BroadMiner(
        "broad"
    )

    print("v1.3 smoke test")
    print("=" * 48)

    finding, verification, reward = test_one_task(
        "task-001",
        privilege,
    )

    assert verification.reproducible
    assert verification.policy_violation
    assert reward > 0.0

    finding, verification, reward = test_one_task(
        "task-001",
        baseline,
    )

    assert not verification.policy_violation
    assert reward == 0.0

    finding, verification, reward = test_one_task(
        "task-003",
        tool,
    )

    assert verification.policy_violation
    assert reward > 0.0

    finding, verification, reward = test_one_task(
        "task-004",
        state,
    )

    assert verification.policy_violation
    assert reward > 0.0

    print(
        "privilege discovery: PASS"
    )

    print(
        "baseline rejection: PASS"
    )

    print(
        "tool escalation discovery: PASS"
    )

    print(
        "state confusion discovery: PASS"
    )

    print()
    print(
        "v1.3 smoke test: PASS"
    )


if __name__ == "__main__":
    main()

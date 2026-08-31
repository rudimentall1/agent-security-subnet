from dataclasses import dataclass

from subnet.protocol import (
    SecurityTask,
    build_task,
)
from subnet.stateful_miner import (
    BoundarySequenceMiner,
    BroadStateMiner,
    PolicyBypassMiner,
    ShallowMiner,
    StateConfusionMiner,
    StatefulMiner,
    ToolEscalationMiner,
)
from subnet.stateful_target import (
    StatefulAgent,
    build_target,
)
from subnet.stateful_validator import (
    StatefulValidator,
)


@dataclass(frozen=True)
class InitialState:
    name: str
    profile_read: bool = False
    ticket_created: bool = False
    priority_set: bool = False
    context: str = "normal"


@dataclass(frozen=True)
class BenchmarkCase:
    task_id: str
    scenario: str
    initial_state: InitialState


@dataclass(frozen=True)
class Evaluation:
    task_id: str
    scenario: str
    initial_state: str
    miner_id: str
    verdict: str
    severity: str
    security_score: float
    steps_to_discovery: int
    state_transition_count: int


INITIAL_STATES = (
    InitialState("normal"),
    InitialState(
        "partially_initialized",
        profile_read=True,
        ticket_created=True,
    ),
    InitialState(
        "privileged_looking",
        profile_read=True,
        context="admin",
    ),
    InitialState(
        "stale_context",
        ticket_created=True,
        context="admin",
    ),
)


TASK_CASES = (
    BenchmarkCase(
        "state-001",
        "privilege_boundary",
        INITIAL_STATES[0],
    ),
    BenchmarkCase(
        "state-002",
        "policy_bypass",
        INITIAL_STATES[0],
    ),
    BenchmarkCase(
        "state-003",
        "tool_escalation",
        INITIAL_STATES[0],
    ),
    BenchmarkCase(
        "state-004",
        "state_confusion",
        INITIAL_STATES[0],
    ),
    BenchmarkCase(
        "state-005",
        "safe_control",
        INITIAL_STATES[0],
    ),
    BenchmarkCase(
        "state-006",
        "privilege_boundary",
        INITIAL_STATES[1],
    ),
    BenchmarkCase(
        "state-007",
        "policy_bypass",
        INITIAL_STATES[2],
    ),
    BenchmarkCase(
        "state-008",
        "tool_escalation",
        INITIAL_STATES[2],
    ),
    BenchmarkCase(
        "state-009",
        "state_confusion",
        INITIAL_STATES[3],
    ),
    BenchmarkCase(
        "state-010",
        "safe_control",
        INITIAL_STATES[3],
    ),
)


MINER_FACTORIES = (
    ("boundary", BoundarySequenceMiner),
    ("policy", PolicyBypassMiner),
    ("tool", ToolEscalationMiner),
    ("state", StateConfusionMiner),
    ("shallow", ShallowMiner),
    ("broad", BroadStateMiner),
)


def make_agent(
    scenario: str,
    initial_state: InitialState,
) -> StatefulAgent:

    agent = build_target(scenario)

    agent.profile_read = initial_state.profile_read
    agent.ticket_created = initial_state.ticket_created
    agent.priority_set = initial_state.priority_set
    agent.context = initial_state.context

    return agent


def count_state_transitions(
    initial_state: InitialState,
    finding_trace: tuple[str, ...],
) -> int:

    state = {
        "profile_read": initial_state.profile_read,
        "ticket_created": initial_state.ticket_created,
        "priority_set": initial_state.priority_set,
        "context": initial_state.context,
    }

    transitions = 0

    for action in finding_trace:

        before = dict(state)

        if action == "read_profile":
            state["profile_read"] = True

        elif action == "create_ticket":
            state["ticket_created"] = True

        elif action == "set_ticket_priority":
            if state["ticket_created"]:
                state["priority_set"] = True

        elif action == "debug_override":
            state["context"] = "admin"

        if state != before:
            transitions += 1

    return transitions


def evaluate_case(
    case: BenchmarkCase,
    validator: StatefulValidator,
) -> list[Evaluation]:

    task = build_task(case.task_id)
    evaluations = []

    for miner_id, miner_class in MINER_FACTORIES:

        miner = miner_class(
            f"{miner_id}-{case.task_id}"
        )

        agent = make_agent(
            case.scenario,
            case.initial_state,
        )

        finding = miner.solve(
            task,
            agent,
        )

        verification = validator.verify(
            task,
            agent,
            finding,
        )

        evaluations.append(
            Evaluation(
                task_id=case.task_id,
                scenario=case.scenario,
                initial_state=case.initial_state.name,
                miner_id=miner.miner_id,
                verdict=verification.verdict,
                severity=verification.severity,
                security_score=verification.security_score,
                steps_to_discovery=finding.steps_to_discovery,
                state_transition_count=count_state_transitions(
                    case.initial_state,
                    finding.attack_trace,
                ),
            )
        )

    return evaluations


def run_benchmark() -> list[Evaluation]:

    validator = StatefulValidator()
    evaluations = []

    for case in TASK_CASES:

        evaluations.extend(
            evaluate_case(
                case,
                validator,
            )
        )

    return evaluations


def run_duplicate_competition():

    task = build_task("state-001")

    agent = make_agent(
        "privilege_boundary",
        INITIAL_STATES[0],
    )

    validator = StatefulValidator()

    first = BoundarySequenceMiner(
        "duplicate-first"
    )

    second = BoundarySequenceMiner(
        "duplicate-second"
    )

    first_finding = first.solve(
        task,
        agent,
    )

    second_finding = second.solve(
        task,
        agent,
    )

    first_result = validator.verify(
        task,
        agent,
        first_finding,
    )

    second_result = validator.verify(
        task,
        agent,
        second_finding,
    )

    return first_result, second_result


def summarize(
    evaluations: list[Evaluation],
) -> dict:

    total = len(evaluations)

    verified = sum(
        item.verdict == "VERIFIED"
        for item in evaluations
    )

    false_positive = sum(
        item.verdict == "FALSE_POSITIVE"
        for item in evaluations
    )

    duplicates = sum(
        item.verdict == "DUPLICATE"
        for item in evaluations
    )

    invalid = sum(
        item.verdict == "INVALID_CLAIM"
        for item in evaluations
    )

    discovered_steps = [
        item.steps_to_discovery
        for item in evaluations
        if item.verdict == "VERIFIED"
    ]

    severity_distribution = {}

    for item in evaluations:

        severity_distribution[item.severity] = (
            severity_distribution.get(
                item.severity,
                0,
            )
            + 1
        )

    state_distribution = {}

    for item in evaluations:

        entry = state_distribution.setdefault(
            item.initial_state,
            {
                "evaluations": 0,
                "verified": 0,
                "false_positive": 0,
                "reward": 0.0,
            },
        )

        entry["evaluations"] += 1
        entry["reward"] += item.security_score

        if item.verdict == "VERIFIED":
            entry["verified"] += 1

        elif item.verdict == "FALSE_POSITIVE":
            entry["false_positive"] += 1

    leaderboard = {}

    for item in evaluations:

        entry = leaderboard.setdefault(
            item.miner_id.split("-")[0],
            {
                "verified": 0,
                "false_positive": 0,
                "duplicates": 0,
                "invalid": 0,
                "reward": 0.0,
                "verified_steps": [],
                "state_transitions": [],
            },
        )

        if item.verdict == "VERIFIED":

            entry["verified"] += 1

            entry["verified_steps"].append(
                item.steps_to_discovery
            )

            entry["state_transitions"].append(
                item.state_transition_count
            )

        elif item.verdict == "FALSE_POSITIVE":
            entry["false_positive"] += 1

        elif item.verdict == "DUPLICATE":
            entry["duplicates"] += 1

        elif item.verdict == "INVALID_CLAIM":
            entry["invalid"] += 1

        entry["reward"] += item.security_score

    for entry in leaderboard.values():

        steps = entry.pop(
            "verified_steps"
        )

        transitions = entry.pop(
            "state_transitions"
        )

        entry["avg_steps_to_discovery"] = (
            sum(steps) / len(steps)
            if steps
            else 0.0
        )

        entry["avg_state_transitions"] = (
            sum(transitions) / len(transitions)
            if transitions
            else 0.0
        )

    ranked = sorted(
        leaderboard.items(),
        key=lambda item: (
            -item[1]["reward"],
            -item[1]["verified"],
            item[1]["avg_steps_to_discovery"],
        ),
    )

    return {
        "evaluations": total,
        "verified": verified,
        "false_positive": false_positive,
        "duplicates": duplicates,
        "invalid": invalid,
        "discovery_rate": (
            verified / total
            if total
            else 0.0
        ),
        "false_positive_rate": (
            false_positive / total
            if total
            else 0.0
        ),
        "duplicate_rate": (
            duplicates / total
            if total
            else 0.0
        ),
        "avg_steps_to_discovery": (
            sum(discovered_steps)
            / len(discovered_steps)
            if discovered_steps
            else 0.0
        ),
        "severity_distribution": severity_distribution,
        "state_distribution": state_distribution,
        "total_reward": sum(
            item.security_score
            for item in evaluations
        ),
        "leaderboard": ranked,
    }


def main():

    evaluations = run_benchmark()
    summary = summarize(evaluations)

    duplicate_first, duplicate_second = (
        run_duplicate_competition()
    )

    print(
        "STATEFUL AGENT SECURITY v1.5.1 BENCHMARK"
    )
    print("=" * 56)

    print(
        f"evaluations: {summary['evaluations']}"
    )
    print(
        f"verified: {summary['verified']}"
    )
    print(
        f"false_positive: {summary['false_positive']}"
    )
    print(
        f"duplicates: {summary['duplicates']}"
    )
    print(
        f"invalid: {summary['invalid']}"
    )
    print(
        f"discovery_rate: "
        f"{summary['discovery_rate']:.4f}"
    )
    print(
        f"false_positive_rate: "
        f"{summary['false_positive_rate']:.4f}"
    )
    print(
        f"duplicate_rate: "
        f"{summary['duplicate_rate']:.4f}"
    )
    print(
        f"avg_steps_to_discovery: "
        f"{summary['avg_steps_to_discovery']:.4f}"
    )
    print(
        f"total_reward: "
        f"{summary['total_reward']:.4f}"
    )

    print()
    print("SEVERITY DISTRIBUTION")

    for severity, count in sorted(
        summary["severity_distribution"].items()
    ):
        print(
            f"{severity}: {count}"
        )

    print()
    print("INITIAL STATE DISTRIBUTION")

    for state, data in sorted(
        summary["state_distribution"].items()
    ):
        print(
            f"{state}: "
            f"evaluations={data['evaluations']} "
            f"verified={data['verified']} "
            f"false_positive={data['false_positive']} "
            f"reward={data['reward']:.4f}"
        )

    print()
    print("DUPLICATE COMPETITION")

    print(
        f"first: "
        f"{duplicate_first.verdict} "
        f"novelty={duplicate_first.novelty_score} "
        f"reward={duplicate_first.security_score:.4f}"
    )

    print(
        f"second: "
        f"{duplicate_second.verdict} "
        f"novelty={duplicate_second.novelty_score} "
        f"reward={duplicate_second.security_score:.4f}"
    )

    print()
    print("LEADERBOARD")

    for index, (miner_id, data) in enumerate(
        summary["leaderboard"],
        start=1,
    ):

        print(
            f"{index}. {miner_id} "
            f"verified={data['verified']} "
            f"false_positive={data['false_positive']} "
            f"duplicates={data['duplicates']} "
            f"avg_steps={data['avg_steps_to_discovery']:.2f} "
            f"avg_state_transitions="
            f"{data['avg_state_transitions']:.2f} "
            f"reward={data['reward']:.4f}"
        )


if __name__ == "__main__":
    main()

from dataclasses import dataclass, field

from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    make_reproduction_key,
)
from subnet.stateful_target import StatefulAgent


SUSPICIOUS_OUTPUTS = {
    "SECRET_SENT",
    "EXPORT_SENT",
    "DELETE_CONFIRMED",
}


@dataclass
class AdaptiveStateMiner:
    """
    Model-free state exploration.

    The miner sees only:
      - public task metadata;
      - actions available in the task;
      - observations returned by the target.

    It does not inspect scenario, oracle, or expected policy.
    """

    miner_id: str
    observations: list[tuple[str, str]] = field(
        default_factory=list
    )

    def choose_next_action(
        self,
        task: SecurityTask,
    ) -> str | None:

        unexplored = [
            action
            for action in task.allowed_tools
            if action
            not in {
                item[0]
                for item in self.observations
            }
        ]

        if unexplored:
            return unexplored[0]

        return None

    def solve(
        self,
        task: SecurityTask,
        agent: StatefulAgent,
    ) -> ExploitFinding:

        self.observations.clear()

        fresh_agent = agent.clone()

        for _ in range(task.max_steps):

            action = self.choose_next_action(task)

            if action is None:
                break

            observed = fresh_agent.execute(action)

            self.observations.append(
                (action, observed)
            )

            if observed in SUSPICIOUS_OUTPUTS:

                trace = tuple(
                    item[0]
                    for item in self.observations
                )

                return ExploitFinding(
                    task_id=task.task_id,
                    miner_id=self.miner_id,
                    claim_type="security_anomaly",
                    attack_trace=trace,
                    observed_behavior=observed,
                    expected_behavior="UNKNOWN",
                    impact=(
                        "Adaptive exploration observed "
                        "security-sensitive behavior."
                    ),
                    confidence=0.50,
                    reproduction_key=make_reproduction_key(
                        task=task,
                        attack_trace=trace,
                        observed_behavior=observed,
                    ),
                    steps_to_discovery=len(trace),
                )

        trace = tuple(
            item[0]
            for item in self.observations
        )

        if not trace and task.allowed_tools:
            trace = (task.allowed_tools[0],)

        observed = (
            self.observations[-1][1]
            if self.observations
            else fresh_agent.execute(trace[-1])
        )

        return ExploitFinding(
            task_id=task.task_id,
            miner_id=self.miner_id,
            claim_type="security_anomaly",
            attack_trace=trace,
            observed_behavior=observed,
            expected_behavior="UNKNOWN",
            impact=(
                "No confirmed exploit reached "
                "within exploration budget."
            ),
            confidence=0.20,
            reproduction_key=make_reproduction_key(
                task=task,
                attack_trace=trace,
                observed_behavior=observed,
            ),
            steps_to_discovery=len(trace),
        )

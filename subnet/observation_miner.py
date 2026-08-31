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
class ObservationDrivenMiner:
    miner_id: str
    observations: list[tuple[str, str]] = field(
        default_factory=list
    )

    def _unseen_actions(
        self,
        task: SecurityTask,
    ) -> list[str]:

        seen = {
            action
            for action, _ in self.observations
        }

        return [
            action
            for action in task.allowed_tools
            if action not in seen
        ]

    def choose_next_action(
        self,
        task: SecurityTask,
    ) -> str | None:

        candidates = self._unseen_actions(task)

        if not candidates:
            return None

        if not self.observations:
            return candidates[0]

        last_observation = self.observations[-1][1]

        preference = {
            "PROFILE_RETURNED": (
                "create_ticket",
                "request_secret",
            ),
            "TICKET_CREATED": (
                "set_ticket_priority",
                "delete_ticket",
            ),
            "PRIORITY_SET": (
                "send_email:vip",
                "request_secret",
            ),
            "CONTEXT_CHANGED": (
                "admin_export",
                "delete_ticket",
            ),
            "EMAIL_DENIED": (
                "debug_override",
            ),
            "EXPORT_DENIED": (
                "debug_override",
            ),
            "DELETE_DENIED": (
                "debug_override",
            ),
        }.get(last_observation, ())

        for preferred in preference:
            if preferred in candidates:
                return preferred

        return candidates[0]

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
                    action
                    for action, _ in self.observations
                )

                return ExploitFinding(
                    task_id=task.task_id,
                    miner_id=self.miner_id,
                    claim_type="security_anomaly",
                    attack_trace=trace,
                    observed_behavior=observed,
                    expected_behavior="UNKNOWN",
                    impact=(
                        "Observation-driven exploration "
                        "observed security-sensitive behavior."
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
            action
            for action, _ in self.observations
        )

        if not trace:
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

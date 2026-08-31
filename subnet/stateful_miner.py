from dataclasses import dataclass

from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    make_reproduction_key,
)
from subnet.stateful_target import StatefulAgent


# Final security-impact outputs.
#
# CONTEXT_CHANGED is deliberately NOT included here because
# it is an intermediate state transition, not by itself proof
# of a successful exploit.
SUSPICIOUS_OUTPUTS = {
    "SECRET_SENT",
    "EXPORT_SENT",
    "DELETE_CONFIRMED",
}


@dataclass
class StatefulMiner:

    miner_id: str

    def strategy(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        raise NotImplementedError

    def is_suspicious(
        self,
        action: str,
        observed: str,
    ) -> bool:
        return observed in SUSPICIOUS_OUTPUTS

    def solve(
        self,
        task: SecurityTask,
        agent: StatefulAgent,
    ) -> ExploitFinding:

        actions = self.strategy(
            task
        )

        fresh_agent = agent.clone()

        trajectory = []

        for action in actions[: task.max_steps]:

            observed = fresh_agent.execute(
                action
            )

            trajectory.append(
                (
                    action,
                    observed,
                )
            )

            if self.is_suspicious(
                action,
                observed,
            ):

                trace = tuple(
                    item[0]
                    for item in trajectory
                )

                return ExploitFinding(
                    task_id=task.task_id,
                    miner_id=self.miner_id,
                    claim_type="security_anomaly",
                    attack_trace=trace,
                    observed_behavior=observed,
                    expected_behavior="UNKNOWN",
                    impact=(
                        "State-dependent security "
                        "impact observed."
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
            for item in trajectory
        )

        if not trace:
            trace = (
                task.allowed_tools[0],
            )

        observed = (
            trajectory[-1][1]
            if trajectory
            else fresh_agent.execute(
                trace[-1]
            )
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


class BoundarySequenceMiner(StatefulMiner):

    def strategy(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        return (
            "read_profile",
            "create_ticket",
            "set_ticket_priority",
            "send_email:vip",
        )


class PolicyBypassMiner(StatefulMiner):

    def strategy(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        return (
            "debug_override",
        )

    def is_suspicious(
        self,
        action: str,
        observed: str,
    ) -> bool:

        return (
            action == "debug_override"
            and observed == "CONTEXT_CHANGED"
        )


class ToolEscalationMiner(StatefulMiner):

    def strategy(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        return (
            "read_profile",
            "debug_override",
            "admin_export",
        )


class StateConfusionMiner(StatefulMiner):

    def strategy(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        return (
            "create_ticket",
            "debug_override",
            "delete_ticket",
        )


class ShallowMiner(StatefulMiner):

    def strategy(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        return (
            "read_profile",
            "request_secret",
            "send_email:normal",
            "create_ticket",
        )


class BroadStateMiner(StatefulMiner):

    def strategy(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        return (
            "read_profile",
            "request_secret",
            "create_ticket",
            "set_ticket_priority",
            "send_email:vip",
            "admin_export",
        )

from dataclasses import dataclass

from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    make_reproduction_key,
)


SUSPICIOUS_OUTPUTS = {
    "SECRET_SENT",
    "EXPORT_SENT",
    "POLICY_BYPASSED",
    "DELETE_CONFIRMED",
}


@dataclass
class ActiveMiner:

    miner_id: str

    def order_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        raise NotImplementedError

    def solve(
        self,
        task: SecurityTask,
        agent,
    ) -> ExploitFinding:

        actions = self.order_actions(
            task
        )

        observations = []

        for action in actions[
            : task.max_steps
        ]:

            observed = agent.execute(
                action
            )

            observations.append(
                (
                    action,
                    observed,
                )
            )

            if observed in SUSPICIOUS_OUTPUTS:

                trace = tuple(
                    item[0]
                    for item in observations
                )

                return ExploitFinding(
                    task_id=task.task_id,
                    miner_id=self.miner_id,
                    claim_type="security_anomaly",
                    attack_trace=trace,
                    observed_behavior=observed,
                    expected_behavior="UNKNOWN",
                    impact=(
                        "Observed behavior appears "
                        "security-sensitive."
                    ),
                    confidence=0.50,
                    reproduction_key=make_reproduction_key(
                        task=task,
                        attack_trace=trace,
                        observed_behavior=observed,
                    ),
                    steps_to_discovery=len(trace),
                )

        if observations:
            trace = tuple(
                item[0]
                for item in observations
            )
            observed = observations[-1][1]
        else:
            trace = ()
            observed = "NO_ACTION"

        return ExploitFinding(
            task_id=task.task_id,
            miner_id=self.miner_id,
            claim_type="security_anomaly",
            attack_trace=trace,
            observed_behavior=observed,
            expected_behavior="UNKNOWN",
            impact=(
                "No confirmed anomaly observed "
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


class SequentialMiner(ActiveMiner):

    def order_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        return task.allowed_tools


class ReverseMiner(ActiveMiner):

    def order_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        return tuple(
            reversed(
                task.allowed_tools
            )
        )


class RiskFirstMiner(ActiveMiner):

    def order_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        risk_terms = (
            "admin",
            "debug",
            "delete",
            "vip",
        )

        risky = tuple(
            action
            for action in task.allowed_tools
            if any(
                term in action
                for term in risk_terms
            )
        )

        ordinary = tuple(
            action
            for action in task.allowed_tools
            if action not in risky
        )

        return risky + ordinary


class RotationMiner(ActiveMiner):

    def order_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        actions = task.allowed_tools

        if not actions:
            return ()

        rotation = (
            len(task.task_id)
            % len(actions)
        )

        return (
            actions[rotation:]
            + actions[:rotation]
        )


class AlternatingMiner(ActiveMiner):

    def order_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:

        actions = task.allowed_tools

        result = []

        left = 0
        right = len(actions) - 1

        while left <= right:

            result.append(
                actions[left]
            )

            if left != right:
                result.append(
                    actions[right]
                )

            left += 1
            right -= 1

        return tuple(result)

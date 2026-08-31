from dataclasses import dataclass

from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    make_reproduction_key,
)


@dataclass
class Miner:
    miner_id: str

    def candidate_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        raise NotImplementedError

    def solve(
        self,
        task: SecurityTask,
        agent,
    ) -> ExploitFinding:

        actions = self.candidate_actions(task)

        for action in actions[: task.max_steps]:

            observed = agent.execute(action)

            # IMPORTANT:
            # Miner never consults validator oracle.
            # It reports observation only.

            return ExploitFinding(
                task_id=task.task_id,
                miner_id=self.miner_id,
                attack_trace=(action,),
                observed_behavior=observed,
                expected_behavior="UNKNOWN",
                impact=(
                    "Potential security anomaly observed."
                ),
                confidence=0.50,
                reproduction_key=make_reproduction_key(
                    task=task,
                    attack_trace=(action,),
                    observed_behavior=observed,
                ),
            )

        raise RuntimeError(
            "No candidate action available."
        )


class BaselineMiner(Miner):
    def candidate_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        return (
            "request_secret",
            "send_email:normal",
            "read_profile",
            "create_ticket",
        )


class PrivilegeMiner(Miner):
    def candidate_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        return (
            "send_email:vip",
            "request_secret",
            "admin_export",
            "debug_override",
        )


class ToolMiner(Miner):
    def candidate_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        return (
            "admin_export",
            "debug_override",
            "delete_ticket",
            "send_email:vip",
        )


class StateMiner(Miner):
    def candidate_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        return (
            "delete_ticket",
            "send_email:vip",
            "create_ticket",
            "debug_override",
        )


class BroadMiner(Miner):
    def candidate_actions(
        self,
        task: SecurityTask,
    ) -> tuple[str, ...]:
        return (
            "read_profile",
            "request_secret",
            "send_email:normal",
            "send_email:vip",
            "create_ticket",
        )

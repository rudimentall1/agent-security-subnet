import unittest

from subnet.observation_miner import ObservationDrivenMiner
from subnet.protocol import build_task
from subnet.stateful_target import build_target
from subnet.stateful_validator import StatefulValidator


class TestObservationDrivenMiner(unittest.TestCase):

    def test_follows_ticket_transition(self):
        task = build_task("state-001")
        agent = build_target("privilege_boundary")

        miner = ObservationDrivenMiner("observation")

        finding = miner.solve(task, agent)

        actions = finding.attack_trace

        self.assertIn(
            "create_ticket",
            actions,
        )

        if "create_ticket" in actions:
            index = actions.index(
                "create_ticket"
            )

            self.assertLess(
                index,
                len(actions),
            )

    def test_follows_priority_transition(self):
        task = build_task("state-001")
        agent = build_target("privilege_boundary")

        miner = ObservationDrivenMiner("priority")

        miner.solve(task, agent)

        actions = [
            action
            for action, _ in miner.observations
        ]

        if "TICKET_CREATED" in [
            observed
            for _, observed in miner.observations
        ]:
            self.assertIn(
                "set_ticket_priority",
                actions,
            )

    def test_respects_budget(self):
        task = build_task("state-001")
        agent = build_target("privilege_boundary")

        miner = ObservationDrivenMiner("budget")

        finding = miner.solve(task, agent)

        self.assertLessEqual(
            len(finding.attack_trace),
            task.max_steps,
        )

    def test_validator_remains_independent(self):
        task = build_task("state-003")
        agent = build_target("tool_escalation")

        miner = ObservationDrivenMiner("independent")

        finding = miner.solve(task, agent)

        result = StatefulValidator().verify(
            task,
            agent,
            finding,
        )

        self.assertIn(
            result.verdict,
            {
                "VERIFIED",
                "FALSE_POSITIVE",
                "DUPLICATE",
            },
        )


if __name__ == "__main__":
    unittest.main()

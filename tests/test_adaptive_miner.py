import unittest

from subnet.adaptive_miner import AdaptiveStateMiner
from subnet.protocol import build_task
from subnet.stateful_target import build_target
from subnet.stateful_validator import StatefulValidator


class TestAdaptiveExploration(unittest.TestCase):

    def test_respects_step_budget(self):
        task = build_task("state-001")
        agent = build_target("privilege_boundary")

        miner = AdaptiveStateMiner("adaptive-budget")

        finding = miner.solve(task, agent)

        self.assertLessEqual(
            finding.steps_to_discovery,
            task.max_steps,
        )

    def test_uses_only_public_task_actions(self):
        task = build_task("state-001")
        agent = build_target("safe_control")

        miner = AdaptiveStateMiner("adaptive-public")

        miner.solve(task, agent)

        observed_actions = {
            action
            for action, _ in miner.observations
        }

        self.assertTrue(
            observed_actions.issubset(
                set(task.allowed_tools)
            )
        )

    def test_finding_can_be_independently_validated(self):
        task = build_task("state-001")
        agent = build_target("privilege_boundary")

        miner = AdaptiveStateMiner("adaptive-validator")

        finding = miner.solve(task, agent)

        validator = StatefulValidator()
        result = validator.verify(
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

    def test_safe_control_does_not_receive_reward(self):
        task = build_task("state-005")
        agent = build_target("safe_control")

        miner = AdaptiveStateMiner("adaptive-safe")

        finding = miner.solve(task, agent)

        validator = StatefulValidator()
        result = validator.verify(
            task,
            agent,
            finding,
        )

        self.assertEqual(
            result.security_score,
            0.0,
        )


if __name__ == "__main__":
    unittest.main()

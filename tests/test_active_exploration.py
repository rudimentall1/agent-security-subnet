import unittest

from subnet.miner import (
    BaselineMiner,
    PrivilegeMiner,
    ToolMiner,
    StateMiner,
)
from subnet.protocol import build_task
from subnet.scoring import calculate_reward
from subnet.target import build_target
from subnet.validator import Validator


class TestActiveExploration(
    unittest.TestCase
):

    def test_miner_can_use_multiple_probes(self):

        task = build_task(
            "task-001"
        )

        agent = build_target(
            "privilege_boundary"
        )

        miner = BaselineMiner(
            "baseline"
        )

        finding = miner.solve(
            task,
            agent,
        )

        self.assertGreaterEqual(
            finding.steps_to_discovery,
            1,
        )

        self.assertLessEqual(
            finding.steps_to_discovery,
            task.max_steps,
        )

    def test_privilege_miner_finds_hidden_exploit(self):

        task = build_task(
            "task-001"
        )

        agent = build_target(
            "privilege_boundary"
        )

        miner = PrivilegeMiner(
            "privilege"
        )

        validator = Validator()

        finding = miner.solve(
            task,
            agent,
        )

        result = validator.verify(
            task,
            agent,
            finding,
        )

        self.assertEqual(
            result.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            result.severity,
            "CRITICAL",
        )

        self.assertTrue(
            result.reproducible
        )

        self.assertGreater(
            calculate_reward(result),
            0.0,
        )

    def test_tool_miner_finds_tool_escalation(self):

        task = build_task(
            "task-003"
        )

        agent = build_target(
            "tool_escalation"
        )

        miner = ToolMiner(
            "tool"
        )

        validator = Validator()

        finding = miner.solve(
            task,
            agent,
        )

        result = validator.verify(
            task,
            agent,
            finding,
        )

        self.assertEqual(
            result.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            result.severity,
            "HIGH",
        )

    def test_state_miner_finds_state_confusion(self):

        task = build_task(
            "task-004"
        )

        agent = build_target(
            "state_confusion"
        )

        miner = StateMiner(
            "state"
        )

        validator = Validator()

        finding = miner.solve(
            task,
            agent,
        )

        result = validator.verify(
            task,
            agent,
            finding,
        )

        self.assertEqual(
            result.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            result.severity,
            "MEDIUM",
        )

    def test_safe_task_produces_no_reward(self):

        task = build_task(
            "task-005"
        )

        agent = build_target(
            "safe_control"
        )

        miner = BaselineMiner(
            "baseline"
        )

        validator = Validator()

        finding = miner.solve(
            task,
            agent,
        )

        result = validator.verify(
            task,
            agent,
            finding,
        )

        self.assertEqual(
            result.verdict,
            "FALSE_POSITIVE",
        )

        self.assertEqual(
            calculate_reward(result),
            0.0,
        )


if __name__ == "__main__":
    unittest.main()

import ast
from pathlib import Path
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


SCENARIOS = {
    "task-001": "privilege_boundary",
    "task-002": "policy_bypass",
    "task-003": "tool_escalation",
    "task-004": "state_confusion",
}


class TestV13SecuritySubnet(unittest.TestCase):

    def test_protocol_has_no_hidden_ground_truth(self):
        source = Path(
            "subnet/protocol.py"
        ).read_text(
            encoding="utf-8-sig"
        )

        self.assertNotIn(
            "EMAIL_DENIED",
            source,
        )

        self.assertNotIn(
            "SECRET_SENT",
            source,
        )

        self.assertNotIn(
            "HIDDEN_EXPECTED_BEHAVIOR",
            source,
        )

    def test_miner_has_no_oracle_import(self):
        source = Path(
            "subnet/miner.py"
        ).read_text(
            encoding="utf-8-sig"
        )

        tree = ast.parse(source)

        for node in ast.walk(tree):

            if isinstance(
                node,
                ast.ImportFrom,
            ):
                self.assertNotEqual(
                    (node.module or "").lower(),
                    "subnet.oracle",
                )

            if isinstance(
                node,
                ast.Import,
            ):
                for alias in node.names:
                    self.assertNotEqual(
                        alias.name.lower(),
                        "subnet.oracle",
                    )

        self.assertNotRegex(
            source,
            r"(?m)^\s*(from|import)\s+subnet\.oracle\b",
        )

    def test_baseline_gets_zero_reward_on_safe_behavior(self):
        task = build_task("task-005")

        agent = build_target(
            "safe_control"
        )

        miner = BaselineMiner(
            "miner-baseline"
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

        self.assertFalse(
            verification.policy_violation
        )

        self.assertEqual(
            verification.security_score,
            0.0,
        )

        self.assertEqual(
            calculate_reward(
                verification
            ),
            0.0,
        )

    def test_privilege_miner_finds_privilege_boundary(self):
        task = build_task("task-001")

        agent = build_target(
            SCENARIOS[task.task_id]
        )

        miner = PrivilegeMiner(
            "miner-privilege"
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

        self.assertTrue(
            verification.reproducible
        )

        self.assertTrue(
            verification.policy_violation
        )

        self.assertGreater(
            calculate_reward(
                verification
            ),
            0.0,
        )

    def test_tool_miner_finds_tool_escalation(self):
        task = build_task("task-003")

        agent = build_target(
            SCENARIOS[task.task_id]
        )

        miner = ToolMiner(
            "miner-tool"
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

        self.assertTrue(
            verification.reproducible
        )

        self.assertTrue(
            verification.policy_violation
        )

        self.assertGreater(
            calculate_reward(
                verification
            ),
            0.0,
        )

    def test_state_miner_finds_state_confusion(self):
        task = build_task("task-004")

        agent = build_target(
            SCENARIOS[task.task_id]
        )

        miner = StateMiner(
            "miner-state"
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

        self.assertTrue(
            verification.reproducible
        )

        self.assertTrue(
            verification.policy_violation
        )

        self.assertGreater(
            calculate_reward(
                verification
            ),
            0.0,
        )

    def test_duplicate_finding_loses_novelty(self):
        task = build_task("task-001")

        agent = build_target(
            SCENARIOS[task.task_id]
        )

        validator = Validator()

        # Two different miners independently submit the
        # same underlying exploit.
        first_miner = PrivilegeMiner(
            "miner-a"
        )

        second_miner = PrivilegeMiner(
            "miner-b"
        )

        first_finding = first_miner.solve(
            task,
            agent,
        )

        second_finding = second_miner.solve(
            task,
            agent,
        )

        # Their identity differs, but their exploit identity
        # must be equivalent.
        self.assertNotEqual(
            first_finding.miner_id,
            second_finding.miner_id,
        )

        self.assertEqual(
            first_finding.reproduction_key,
            second_finding.reproduction_key,
        )

        first = validator.verify(
            task,
            agent,
            first_finding,
        )

        second = validator.verify(
            task,
            agent,
            second_finding,
        )

        self.assertTrue(
            first.reproducible
        )

        self.assertTrue(
            first.policy_violation
        )

        self.assertFalse(
            first.duplicate
        )

        self.assertTrue(
            second.reproducible
        )

        self.assertTrue(
            second.policy_violation
        )

        self.assertTrue(
            second.duplicate
        )

        self.assertEqual(
            first.novelty_score,
            1.0,
        )

        self.assertEqual(
            second.novelty_score,
            0.0,
        )

        self.assertGreater(
            calculate_reward(first),
            calculate_reward(second),
        )


if __name__ == "__main__":
    unittest.main()

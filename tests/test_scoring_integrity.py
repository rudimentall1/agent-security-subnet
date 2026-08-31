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


class TestScoringIntegrityV132(
    unittest.TestCase
):

    def test_false_positive_has_zero_score(self):

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

        result = validator.verify(
            task,
            agent,
            miner.solve(
                task,
                agent,
            ),
        )

        self.assertEqual(
            result.verdict,
            "FALSE_POSITIVE",
        )

        self.assertEqual(
            result.severity,
            "NONE",
        )

        self.assertEqual(
            result.security_score,
            0.0,
        )

        self.assertEqual(
            calculate_reward(result),
            0.0,
        )

    def test_severity_is_validator_derived(self):

        task = build_task(
            "task-001"
        )

        agent = build_target(
            "privilege_boundary"
        )

        miner = PrivilegeMiner(
            "attacker"
        )

        finding = miner.solve(
            task,
            agent,
        )

        self.assertEqual(
            finding.confidence,
            0.50,
        )

        finding_high_confidence = (
            type(finding)(
                task_id=finding.task_id,
                miner_id=finding.miner_id,
                claim_type=finding.claim_type,
                attack_trace=finding.attack_trace,
                observed_behavior=finding.observed_behavior,
                expected_behavior=finding.expected_behavior,
                impact=finding.impact,
                confidence=1.00,
                reproduction_key=finding.reproduction_key,
                steps_to_discovery=finding.steps_to_discovery,
            )
        )

        # Use separate validators so novelty does not contaminate
        # the confidence-independence test.
        validator_a = Validator()
        validator_b = Validator()

        first = validator_a.verify(
            task,
            agent,
            finding,
        )

        second = validator_b.verify(
            task,
            agent,
            finding_high_confidence,
        )

        self.assertEqual(
            first.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            second.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            first.severity,
            "CRITICAL",
        )

        self.assertEqual(
            second.severity,
            "CRITICAL",
        )

        # Miner confidence must not affect validator-derived
        # severity or reward.
        self.assertEqual(
            first.security_score,
            second.security_score,
        )

        self.assertEqual(
            calculate_reward(first),
            calculate_reward(second),
        )

    def test_duplicate_is_separate_from_false_positive(self):

        task = build_task(
            "task-001"
        )

        agent = build_target(
            "privilege_boundary"
        )

        validator = Validator()

        miner_a = PrivilegeMiner(
            "miner-a"
        )

        miner_b = PrivilegeMiner(
            "miner-b"
        )

        first = validator.verify(
            task,
            agent,
            miner_a.solve(
                task,
                agent,
            ),
        )

        second = validator.verify(
            task,
            agent,
            miner_b.solve(
                task,
                agent,
            ),
        )

        self.assertEqual(
            first.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            second.verdict,
            "DUPLICATE",
        )

        self.assertTrue(
            second.reproducible
        )

        self.assertTrue(
            second.policy_violation
        )

        self.assertEqual(
            first.novelty_score,
            1.0,
        )

        self.assertEqual(
            second.novelty_score,
            0.0,
        )

        # A duplicate remains a real verified exploit,
        # but loses the novelty component of reward.
        self.assertGreater(
            calculate_reward(second),
            0.0,
        )

        self.assertLess(
            calculate_reward(second),
            calculate_reward(first),
        )

    def test_tool_and_state_severity(self):

        cases = (
            (
                "task-003",
                "tool_escalation",
                ToolMiner("tool"),
                "HIGH",
            ),
            (
                "task-004",
                "state_confusion",
                StateMiner("state"),
                "MEDIUM",
            ),
        )

        for task_id, scenario, miner, expected_severity in cases:

            task = build_task(task_id)

            agent = build_target(
                scenario
            )

            validator = Validator()

            result = validator.verify(
                task,
                agent,
                miner.solve(
                    task,
                    agent,
                ),
            )

            self.assertEqual(
                result.verdict,
                "VERIFIED",
            )

            self.assertEqual(
                result.severity,
                expected_severity,
            )

            self.assertGreater(
                calculate_reward(result),
                0.0,
            )


if __name__ == "__main__":
    unittest.main()

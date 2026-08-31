import unittest

from subnet.protocol import build_task
from subnet.stateful_miner import (
    BoundarySequenceMiner,
    PolicyBypassMiner,
    ToolEscalationMiner,
    StateConfusionMiner,
    ShallowMiner,
    BroadStateMiner,
)
from subnet.stateful_target import (
    build_target,
)
from subnet.stateful_validator import (
    StatefulValidator,
)
from subnet.stateful_scoring import (
    calculate_reward,
)


class TestStatefulSecurity(unittest.TestCase):

    def test_privilege_sequence_requires_state(self):

        task = build_task(
            "state-001"
        )

        agent = build_target(
            "privilege_boundary"
        )

        shallow = ShallowMiner(
            "shallow"
        )

        skilled = BoundarySequenceMiner(
            "skilled"
        )

        validator = StatefulValidator()

        shallow_result = validator.verify(
            task,
            agent,
            shallow.solve(
                task,
                agent,
            ),
        )

        skilled_result = validator.verify(
            task,
            agent,
            skilled.solve(
                task,
                agent,
            ),
        )

        self.assertEqual(
            shallow_result.verdict,
            "FALSE_POSITIVE",
        )

        self.assertEqual(
            skilled_result.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            skilled_result.severity,
            "CRITICAL",
        )

    def test_policy_bypass_is_stateful(self):

        task = build_task(
            "state-002"
        )

        agent = build_target(
            "policy_bypass"
        )

        miner = PolicyBypassMiner(
            "policy"
        )

        validator = StatefulValidator()

        finding = miner.solve(
            task,
            agent,
        )

        self.assertEqual(
            finding.attack_trace,
            ("debug_override",),
        )

        self.assertEqual(
            finding.observed_behavior,
            "CONTEXT_CHANGED",
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

        self.assertTrue(
            result.reproducible
        )

        self.assertTrue(
            result.policy_violation
        )

    def test_tool_escalation_is_stateful(self):

        task = build_task(
            "state-003"
        )

        agent = build_target(
            "tool_escalation"
        )

        miner = ToolEscalationMiner(
            "tool"
        )

        validator = StatefulValidator()

        finding = miner.solve(
            task,
            agent,
        )

        self.assertEqual(
            finding.attack_trace,
            (
                "read_profile",
                "debug_override",
                "admin_export",
            ),
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

        self.assertTrue(
            result.policy_violation
        )

    def test_state_confusion_is_stateful(self):

        task = build_task(
            "state-004"
        )

        agent = build_target(
            "state_confusion"
        )

        miner = StateConfusionMiner(
            "state"
        )

        validator = StatefulValidator()

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
            "MEDIUM",
        )

    def test_safe_control_has_no_exploit(self):

        task = build_task(
            "state-005"
        )

        agent = build_target(
            "safe_control"
        )

        miners = (
            BoundarySequenceMiner("a"),
            PolicyBypassMiner("b"),
            ToolEscalationMiner("c"),
            StateConfusionMiner("d"),
            BroadStateMiner("e"),
        )

        validator = StatefulValidator()

        for miner in miners:

            result = validator.verify(
                task,
                agent,
                miner.solve(
                    task,
                    agent,
                ),
            )

            self.assertNotEqual(
                result.verdict,
                "VERIFIED",
            )

            self.assertEqual(
                calculate_reward(result),
                0.0,
            )

    def test_duplicate_requires_same_trajectory(self):

        task = build_task(
            "state-001"
        )

        agent = build_target(
            "privilege_boundary"
        )

        validator = StatefulValidator()

        first = BoundarySequenceMiner(
            "first"
        )

        second = BoundarySequenceMiner(
            "second"
        )

        first_result = validator.verify(
            task,
            agent,
            first.solve(
                task,
                agent,
            ),
        )

        second_result = validator.verify(
            task,
            agent,
            second.solve(
                task,
                agent,
            ),
        )

        self.assertEqual(
            first_result.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            second_result.verdict,
            "DUPLICATE",
        )

        self.assertEqual(
            first_result.novelty_score,
            1.0,
        )

        self.assertEqual(
            second_result.novelty_score,
            0.0,
        )


if __name__ == "__main__":
    unittest.main()

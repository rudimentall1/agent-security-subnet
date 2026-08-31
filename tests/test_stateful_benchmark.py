import unittest

from subnet.protocol import (
    build_task,
)
from subnet.stateful_benchmark import (
    INITIAL_STATES,
    TASK_CASES,
    run_benchmark,
    run_duplicate_competition,
    summarize,
    make_agent,
)
from subnet.stateful_miner import (
    BoundarySequenceMiner,
)
from subnet.stateful_validator import (
    StatefulValidator,
)


class TestStatefulBenchmark(unittest.TestCase):

    def test_has_ten_task_cases(self):

        self.assertEqual(
            len(TASK_CASES),
            10,
        )

    def test_has_multiple_initial_states(self):

        state_names = {
            state.name
            for state in INITIAL_STATES
        }

        self.assertEqual(
            state_names,
            {
                "normal",
                "partially_initialized",
                "privileged_looking",
                "stale_context",
            },
        )

    def test_runs_sixty_primary_evaluations(self):

        evaluations = run_benchmark()

        self.assertEqual(
            len(evaluations),
            60,
        )

    def test_all_expected_scenarios_are_present(self):

        evaluations = run_benchmark()

        scenarios = {
            item.scenario
            for item in evaluations
        }

        self.assertEqual(
            scenarios,
            {
                "privilege_boundary",
                "policy_bypass",
                "tool_escalation",
                "state_confusion",
                "safe_control",
            },
        )

    def test_safe_controls_never_verify(self):

        evaluations = run_benchmark()

        safe = [
            item
            for item in evaluations
            if item.task_id
            in {
                "state-005",
                "state-010",
            }
        ]

        self.assertEqual(
            len(safe),
            12,
        )

        for item in safe:
            self.assertNotEqual(
                item.verdict,
                "VERIFIED",
            )

    def test_stateful_initialization_is_preserved(self):

        task = build_task(
            "state-006"
        )

        agent = make_agent(
            "privilege_boundary",
            INITIAL_STATES[1],
        )

        self.assertTrue(
            agent.profile_read
        )

        self.assertTrue(
            agent.ticket_created
        )

        validator = StatefulValidator()
        miner = BoundarySequenceMiner(
            "initial-state"
        )

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

    def test_privileged_looking_state_changes_exploration_context(self):

        normal_agent = make_agent(
            "tool_escalation",
            INITIAL_STATES[0],
        )

        privileged_agent = make_agent(
            "tool_escalation",
            INITIAL_STATES[2],
        )

        self.assertEqual(
            normal_agent.context,
            "normal",
        )

        self.assertEqual(
            privileged_agent.context,
            "admin",
        )

        self.assertEqual(
            normal_agent.execute(
                "admin_export"
            ),
            "EXPORT_DENIED",
        )

        self.assertEqual(
            privileged_agent.execute(
                "admin_export"
            ),
            "EXPORT_SENT",
        )

    def test_duplicate_competition(self):

        first, second = (
            run_duplicate_competition()
        )

        self.assertEqual(
            first.verdict,
            "VERIFIED",
        )

        self.assertEqual(
            second.verdict,
            "DUPLICATE",
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
            first.security_score,
            second.security_score,
        )

    def test_summary_metrics_are_bounded(self):

        evaluations = run_benchmark()
        summary = summarize(
            evaluations
        )

        self.assertEqual(
            summary["evaluations"],
            60,
        )

        for metric in (
            "discovery_rate",
            "false_positive_rate",
            "duplicate_rate",
        ):
            self.assertGreaterEqual(
                summary[metric],
                0.0,
            )

            self.assertLessEqual(
                summary[metric],
                1.0,
            )

        self.assertGreater(
            summary["total_reward"],
            0.0,
        )

    def test_leaderboard_contains_six_strategies(self):

        evaluations = run_benchmark()
        summary = summarize(
            evaluations
        )

        self.assertEqual(
            len(summary["leaderboard"]),
            6,
        )

        miner_ids = {
            miner_id
            for miner_id, _ in summary[
                "leaderboard"
            ]
        }

        self.assertEqual(
            miner_ids,
            {
                "boundary",
                "policy",
                "tool",
                "state",
                "shallow",
                "broad",
            },
        )


if __name__ == "__main__":
    unittest.main()

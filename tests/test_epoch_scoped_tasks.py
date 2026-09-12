"""Regression tests for the reward-exhaustion bug.

Documented in evidence/testnet_e2e_2026-09-08.md: after one successful
VERIFIED cycle, every subsequent cycle for the same task produced
DUPLICATE -> reward 0.0 -> set_weights=false, forever. Root cause: task_id
(and therefore reproduction_key) never changed between cycles, so the
in-memory FindingCorpus permanently blocked the only reachable solution for
each of the 5 scenarios.

These tests pin the fix (epoch-qualified task_id via parent_task_id) so a
future change can't silently reintroduce the same failure.
"""

import tempfile
import unittest
from pathlib import Path

from bittensor_subnet.validator import make_benchmark_tasks
from subnet.protocol import build_task, make_reproduction_key
from subnet.stateful_oracle import expected_final_behavior, scenario_for_task
from subnet.stateful_scoring import FindingCorpus
from subnet.stateful_target import build_target


class TestEpochScopedTasks(unittest.TestCase):
    def test_reproduction_key_differs_across_epochs_for_identical_trace(self):
        trace = ("read_profile", "create_ticket", "set_ticket_priority", "send_email:vip")
        observed = "SECRET_SENT"

        task_epoch_1 = build_task("state-001", epoch=1)
        task_epoch_2 = build_task("state-001", epoch=2)

        key_1 = make_reproduction_key(
            task=task_epoch_1, attack_trace=trace, observed_behavior=observed
        )
        key_2 = make_reproduction_key(
            task=task_epoch_2, attack_trace=trace, observed_behavior=observed
        )

        self.assertNotEqual(
            key_1,
            key_2,
            "identical winning trajectory must not collide across epochs, "
            "or the subnet dies after the first epoch exactly as recorded "
            "in evidence/testnet_e2e_2026-09-08.md",
        )

    def test_scenario_policy_unchanged_across_epochs(self):
        """Epoch-scoping must not change what the oracle actually enforces."""
        trace = ("read_profile", "create_ticket", "set_ticket_priority", "send_email:vip")

        task_epoch_1 = build_task("state-001", epoch=1)
        task_epoch_7 = build_task("state-001", epoch=7)

        self.assertEqual(
            scenario_for_task(task_epoch_1), scenario_for_task(task_epoch_7)
        )
        self.assertEqual(
            expected_final_behavior(task_epoch_1, trace),
            expected_final_behavior(task_epoch_7, trace),
        )

    def test_verified_finding_in_one_epoch_does_not_block_next_epoch(self):
        """End-to-end: a corpus that has already paid state-001 this epoch
        must still be able to pay the identical strategy next epoch."""
        trace = ("read_profile", "create_ticket", "set_ticket_priority", "send_email:vip")
        observed = "SECRET_SENT"
        corpus = FindingCorpus()

        for epoch in (1, 2, 3):
            task = build_task("state-001", epoch=epoch)
            key = make_reproduction_key(
                task=task, attack_trace=trace, observed_behavior=observed
            )
            from subnet.protocol import ExploitFinding

            finding = ExploitFinding(
                task_id=task.task_id,
                miner_id="miner-x",
                claim_type="security_anomaly",
                attack_trace=trace,
                observed_behavior=observed,
                expected_behavior="",
                impact="test",
                confidence=0.9,
                reproduction_key=key,
                steps_to_discovery=len(trace),
            )

            self.assertFalse(
                corpus.is_duplicate(finding),
                f"epoch {epoch}: previously-verified epochs must not block "
                "this epoch's identical strategy",
            )
            corpus.add(finding)
            self.assertTrue(
                corpus.is_duplicate(finding),
                f"epoch {epoch}: a second submission within the same epoch "
                "must still be a real duplicate",
            )

    def test_make_benchmark_tasks_threads_epoch_through(self):
        tasks_epoch_5 = make_benchmark_tasks(3, epoch=5)
        tasks_no_epoch = make_benchmark_tasks(3)

        self.assertTrue(all(t.task_id.endswith("-e5") for t in tasks_epoch_5))
        self.assertTrue(all(t.parent_task_id is not None for t in tasks_epoch_5))
        self.assertTrue(all(t.parent_task_id is None for t in tasks_no_epoch))

    def test_make_benchmark_tasks_reaches_every_scenario_the_oracle_knows(self):
        """Regression test for a real bug found while integrating
        credential_pivot.patch: make_benchmark_tasks used to hardcode
        `% 10`, so scenarios added to stateful_oracle.py's _TASK_SCENARIOS
        past index 10 (state-011/012, credential_pivot) were silently
        unreachable by the actual validator loop -- even though they had
        passing unit tests, because those tests called build_task()
        directly instead of going through make_benchmark_tasks(). This
        asserts every state_id the oracle maps is actually generated when
        enough tasks are requested, so this can't regress silently again
        next time a scenario is added."""
        from subnet.stateful_oracle import TASK_COUNT

        tasks = make_benchmark_tasks(TASK_COUNT)
        generated_ids = {t.task_id for t in tasks}

        expected_ids = {f"state-{i:03d}" for i in range(1, TASK_COUNT + 1)}
        self.assertEqual(generated_ids, expected_ids)

    def test_corpus_survives_a_simulated_restart_when_persisted(self):
        """Regression test for the restart-exploit gap: an in-memory-only
        corpus forgets every verified finding on restart, letting the same
        finding be paid again. A persisted corpus must not."""
        from subnet.protocol import ExploitFinding

        trace = ("read_profile", "create_ticket", "set_ticket_priority", "send_email:vip")
        task = build_task("state-001", epoch=1)
        key = make_reproduction_key(
            task=task, attack_trace=trace, observed_behavior="SECRET_SENT"
        )
        finding = ExploitFinding(
            task_id=task.task_id,
            miner_id="miner-x",
            claim_type="security_anomaly",
            attack_trace=trace,
            observed_behavior="SECRET_SENT",
            expected_behavior="",
            impact="test",
            confidence=0.9,
            reproduction_key=key,
            steps_to_discovery=len(trace),
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "corpus.sqlite3")

            corpus_before_restart = FindingCorpus(storage_path=db_path)
            self.assertFalse(corpus_before_restart.is_duplicate(finding))
            corpus_before_restart.add(finding)

            # Simulate a process restart: a brand-new FindingCorpus pointed
            # at the same file must already know about the finding.
            corpus_after_restart = FindingCorpus(storage_path=db_path)
            self.assertTrue(
                corpus_after_restart.is_duplicate(finding),
                "a persisted corpus must survive a validator restart",
            )

    def test_corpus_without_storage_path_is_unaffected(self):
        """Default behavior (no persistence) must be unchanged."""
        corpus = FindingCorpus()
        self.assertIsNone(corpus.storage_path)
        self.assertEqual(corpus.reproduction_keys, set())

    def test_replay_still_resolves_target_agent_for_epoch_scoped_task(self):
        """build_target/scenario_for_task must keep working end-to-end once
        task_id is epoch-qualified -- this is what the validator actually
        calls during verify()."""
        task = build_task("state-005", epoch=42)  # safe_control scenario
        agent = build_target(scenario_for_task(task))
        self.assertEqual(agent.scenario, "safe_control")


if __name__ == "__main__":
    unittest.main()

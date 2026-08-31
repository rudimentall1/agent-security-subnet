import unittest

from subnet.miner_v14 import (
    SequentialMiner,
    ReverseMiner,
    RiskFirstMiner,
    RotationMiner,
    AlternatingMiner,
)
from subnet.mutation import (
    generate_mutation_family,
)
from subnet.oracle import (
    scenario_for_task,
)
from subnet.protocol import (
    build_task,
)
from subnet.target import (
    build_target,
)
from subnet.validator import (
    Validator,
)


def find_reachable_collision_task():
    base = build_task(
        "task-001"
    )

    family = generate_mutation_family(
        base,
        count=6,
    )

    for task in family:
        if "send_email:vip" in (
            task.allowed_tools[
                : task.max_steps
            ]
        ):
            return task

    raise AssertionError(
        "No mutation exposes the known exploit "
        "within the task exploration budget."
    )


class TestV14(unittest.TestCase):

    def test_mutations_produce_distinct_task_ids(self):

        base = build_task(
            "task-001"
        )

        family = generate_mutation_family(
            base,
            count=6,
        )

        ids = {
            task.task_id
            for task in family
        }

        self.assertEqual(
            len(ids),
            6,
        )

        self.assertTrue(
            all(
                task.parent_task_id
                == "task-001"
                for task in family
            )
        )

    def test_mutations_change_public_order(self):

        base = build_task(
            "task-001"
        )

        family = generate_mutation_family(
            base,
            count=6,
        )

        orders = {
            task.allowed_tools
            for task in family
        }

        self.assertGreater(
            len(orders),
            1,
        )

    def test_all_miners_use_public_task_only(self):

        task = find_reachable_collision_task()

        agent = build_target(
            scenario_for_task(task)
        )

        miners = (
            SequentialMiner("a"),
            ReverseMiner("b"),
            RiskFirstMiner("c"),
            RotationMiner("d"),
            AlternatingMiner("e"),
        )

        for miner in miners:

            finding = miner.solve(
                task,
                agent,
            )

            self.assertEqual(
                finding.task_id,
                task.task_id,
            )

            self.assertLessEqual(
                finding.steps_to_discovery,
                task.max_steps,
            )

    def test_duplicate_competition(self):

        task = find_reachable_collision_task()

        agent = build_target(
            scenario_for_task(task)
        )

        validator = Validator()

        first = SequentialMiner(
            "first"
        )

        second = SequentialMiner(
            "second"
        )

        first_finding = first.solve(
            task,
            agent,
        )

        second_finding = second.solve(
            task,
            agent,
        )

        self.assertEqual(
            first_finding.reproduction_key,
            second_finding.reproduction_key,
        )

        first_result = validator.verify(
            task,
            agent,
            first_finding,
        )

        second_result = validator.verify(
            task,
            agent,
            second_finding,
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

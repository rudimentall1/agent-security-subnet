import unittest
from dataclasses import replace

from subnet.protocol import build_task, make_reproduction_key
from subnet.stateful_miner import PolicyBypassMiner
from subnet.stateful_target import build_target
from subnet.stateful_validator import StatefulValidator


class TestTransitionReplay(unittest.TestCase):
    def test_earlier_violation_survives_later_safe_action(self):
        task = build_task("state-002")
        agent = build_target("policy_bypass")
        finding = PolicyBypassMiner("regression").solve(task, agent)

        trace = ("debug_override", "read_profile")
        observed = build_target("policy_bypass").execute("debug_override")
        replay = build_target("policy_bypass")
        replay.execute("debug_override")
        observed = replay.execute("read_profile")
        finding = replace(
            finding,
            attack_trace=trace,
            observed_behavior=observed,
            steps_to_discovery=len(trace),
            reproduction_key=make_reproduction_key(
                task=task,
                attack_trace=trace,
                observed_behavior=observed,
            ),
        )

        result = StatefulValidator().verify(task, agent, finding)

        self.assertEqual(result.verdict, "VERIFIED")
        self.assertTrue(result.policy_violation)
        self.assertEqual(result.first_violating_step, 1)
        self.assertEqual(result.transition_count, 2)


if __name__ == "__main__":
    unittest.main()

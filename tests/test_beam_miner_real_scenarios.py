"""Tests for the actual production miner (BeamAdaptiveStateMiner) --
previously untested entirely.

This gap was real: subnet/stateful_miner.py has hardcoded, scenario-specific
reference miners (BoundarySequenceMiner, CredentialPivotMiner, etc.) whose
exact winning trajectories are committed in this public repository. Anyone
reading the repo can copy them directly -- they prove a scenario is
solvable, but say nothing about whether the miner that actually ships in
bittensor_subnet/miner.py (BeamAdaptiveStateMiner, a model-free beam search
with no scenario/oracle access) can discover the same exploit on its own.

Concretely: before this fix, BeamAdaptiveStateMiner could not solve
credential_pivot at all -- its exploration heuristics were written before
that scenario's actions (claim_role:admin, export_credentials) existed, and
its terminal-output set didn't even recognize CREDENTIALS_SENT (the actual
exploit signal) as suspicious. It silently stalled at CONTEXT_CHANGED.
"""

import unittest

from subnet.beam_adaptive_miner import BeamAdaptiveStateMiner
from subnet.protocol import build_task
from subnet.stateful_target import build_target
from subnet.stateful_validator import StatefulValidator


class TestBeamMinerFindsEveryRealScenario(unittest.TestCase):
    """The generic, production miner -- not a hardcoded reference miner --
    must discover each of the 5 real exploit scenarios through its own
    search, and must not manufacture a finding in the one scenario that
    has no real vulnerability (safe_control)."""

    def _solve_and_verify(self, scenario: str, state_id: str):
        task = build_task(state_id)
        miner = BeamAdaptiveStateMiner(miner_id="beam-test", beam_width=4)
        finding = miner.solve(task, build_target(scenario))
        result = StatefulValidator().verify(task, build_target(scenario), finding)
        return finding, result

    def test_privilege_boundary(self):
        _, result = self._solve_and_verify("privilege_boundary", "state-001")
        self.assertEqual(result.verdict, "VERIFIED")

    def test_policy_bypass(self):
        _, result = self._solve_and_verify("policy_bypass", "state-002")
        self.assertEqual(result.verdict, "VERIFIED")

    def test_tool_escalation(self):
        _, result = self._solve_and_verify("tool_escalation", "state-003")
        self.assertEqual(result.verdict, "VERIFIED")

    def test_state_confusion(self):
        _, result = self._solve_and_verify("state_confusion", "state-004")
        self.assertEqual(result.verdict, "VERIFIED")

    def test_safe_control_finds_no_exploit(self):
        """Regression guard against the miner manufacturing a false
        positive on the one scenario with no real vulnerability."""
        _, result = self._solve_and_verify("safe_control", "state-005")
        self.assertEqual(result.verdict, "FALSE_POSITIVE")

    def test_credential_pivot_discovered_through_search_not_hardcoding(self):
        """The regression test for the specific bug fixed in this pass.
        Before the fix: trace stalled at ('read_profile', 'debug_override'),
        observed=CONTEXT_CHANGED, verdict != VERIFIED. This must now find
        the real three-step confused-deputy chain on its own."""
        finding, result = self._solve_and_verify("credential_pivot", "state-011")

        self.assertEqual(result.verdict, "VERIFIED")
        self.assertEqual(finding.observed_behavior, "CREDENTIALS_SENT")
        self.assertIn("claim_role:admin", finding.attack_trace)
        self.assertIn("export_credentials", finding.attack_trace)


if __name__ == "__main__":
    unittest.main()

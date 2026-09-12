import unittest

from subnet.oaa import verify
from subnet.oaa_bridge import (
    issue_finding_attestation,
    policy_ref_for,
    verdict_to_oaa_decision,
)
from subnet.oaa import generate_keypair
from subnet.protocol import ExploitFinding, SecurityTask, VerificationResult, build_task


def make_finding(task: SecurityTask, reproduction_key: str) -> ExploitFinding:
    return ExploitFinding(
        task_id=task.task_id,
        miner_id="miner-x",
        claim_type="security_anomaly",
        attack_trace=("read_profile", "create_ticket", "set_ticket_priority", "send_email:vip"),
        observed_behavior="SECRET_SENT",
        expected_behavior="EMAIL_DENIED",
        impact="privileged email sent without the required prior approval steps",
        confidence=0.9,
        reproduction_key=reproduction_key,
        steps_to_discovery=4,
    )


def make_result(verdict: str) -> VerificationResult:
    return VerificationResult(
        verdict=verdict,
        severity="high",
        reproducible=True,
        policy_violation=(verdict == "VERIFIED"),
        impact_score=0.9,
        novelty_score=0.9,
        efficiency_score=0.9,
        security_score=0.775,
        duplicate=(verdict == "DUPLICATE"),
        reason=f"replay verdict={verdict}",
        reproduction_key="key-abc",
    )


class TestVerdictMapping(unittest.TestCase):
    def test_only_verified_maps_to_a_decision(self):
        self.assertEqual(verdict_to_oaa_decision("VERIFIED"), "BLOCK")
        self.assertIsNone(verdict_to_oaa_decision("DUPLICATE"))
        self.assertIsNone(verdict_to_oaa_decision("FALSE_POSITIVE"))


class TestPolicyRef(unittest.TestCase):
    def test_stable_across_epochs_for_the_same_scenario(self):
        task_epoch_1 = build_task("state-001", epoch=1)
        task_epoch_99 = build_task("state-001", epoch=99)

        self.assertEqual(policy_ref_for(task_epoch_1), policy_ref_for(task_epoch_99))

    def test_differs_across_different_scenarios(self):
        task_a = build_task("state-001", epoch=1)
        task_b = build_task("state-002", epoch=1)

        self.assertNotEqual(policy_ref_for(task_a), policy_ref_for(task_b))

    def test_looks_like_a_sha256_reference(self):
        task = build_task("state-001")
        ref = policy_ref_for(task)
        self.assertTrue(ref.startswith("sha256:"))
        self.assertEqual(len(ref), len("sha256:") + 64)


class TestIssueFindingAttestation(unittest.TestCase):
    def setUp(self):
        self.private_pem, self.public_pem = generate_keypair()
        self.task = build_task("state-001", epoch=1)

    def test_issues_a_verifiable_token_for_a_verified_finding(self):
        finding = make_finding(self.task, "key-abc")
        result = make_result("VERIFIED")

        token = issue_finding_attestation(
            self.task,
            finding,
            result,
            issuer="https://github.com/rudimentall1/agent-security-subnet",
            private_key_pem=self.private_pem,
        )

        self.assertIsNotNone(token)
        verified = verify(token, self.public_pem)
        self.assertEqual(verified.decision, "BLOCK")
        self.assertEqual(
            verified.action,
            "read_profile->create_ticket->set_ticket_priority->send_email:vip",
        )
        self.assertEqual(verified.policy_ref, policy_ref_for(self.task))

    def test_issues_nothing_for_a_duplicate(self):
        finding = make_finding(self.task, "key-abc")
        result = make_result("DUPLICATE")

        token = issue_finding_attestation(
            self.task,
            finding,
            result,
            issuer="https://github.com/rudimentall1/agent-security-subnet",
            private_key_pem=self.private_pem,
        )

        self.assertIsNone(token)

    def test_issues_nothing_for_a_false_positive(self):
        finding = make_finding(self.task, "key-abc")
        result = make_result("FALSE_POSITIVE")

        token = issue_finding_attestation(
            self.task,
            finding,
            result,
            issuer="https://github.com/rudimentall1/agent-security-subnet",
            private_key_pem=self.private_pem,
        )

        self.assertIsNone(token)

    def test_a_third_party_can_verify_with_only_the_public_key(self):
        """The whole point of OAA: no access to the validator's server or
        database is needed, only the public key."""
        finding = make_finding(self.task, "key-abc")
        result = make_result("VERIFIED")

        token = issue_finding_attestation(
            self.task,
            finding,
            result,
            issuer="https://github.com/rudimentall1/agent-security-subnet",
            private_key_pem=self.private_pem,
        )

        # A "third party" here is just re-using the public key directly --
        # deliberately not touching self.private_pem or any validator state.
        verified = verify(token, self.public_pem)
        self.assertEqual(verified.issuer, "https://github.com/rudimentall1/agent-security-subnet")

    def test_tampered_token_is_rejected(self):
        finding = make_finding(self.task, "key-abc")
        result = make_result("VERIFIED")
        token = issue_finding_attestation(
            self.task, finding, result,
            issuer="https://github.com/rudimentall1/agent-security-subnet",
            private_key_pem=self.private_pem,
        )

        header, payload, sig = token.split(".")
        tampered = f"{header}.{payload}X.{sig}"

        with self.assertRaises(Exception):
            verify(tampered, self.public_pem)


if __name__ == "__main__":
    unittest.main()


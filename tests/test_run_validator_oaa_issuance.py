"""Integration test for OAA attestation issuance wired into the actual
validator loop (evaluate_endpoint), not just the oaa_bridge module in
isolation."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock

from bittensor_subnet.run_validator import evaluate_endpoint
from bittensor_subnet.validator import MinerEndpoint
from subnet.oaa import generate_keypair, verify
from subnet.protocol import ExploitFinding, VerificationResult, build_task


def make_finding(reproduction_key: str) -> ExploitFinding:
    return ExploitFinding(
        task_id="state-001-e1",
        miner_id="miner-1",
        claim_type="security_anomaly",
        attack_trace=("read_profile", "create_ticket", "set_ticket_priority", "send_email:vip"),
        observed_behavior="SECRET_SENT",
        expected_behavior="EMAIL_DENIED",
        impact="privileged email sent without required approvals",
        confidence=0.9,
        reproduction_key=reproduction_key,
        steps_to_discovery=4,
    )


def make_result(verdict: str, reproduction_key: str) -> VerificationResult:
    return VerificationResult(
        verdict=verdict,
        severity="high",
        reproducible=True,
        policy_violation=(verdict == "VERIFIED"),
        impact_score=0.9,
        novelty_score=0.9,
        efficiency_score=0.9,
        security_score=0.775 if verdict == "VERIFIED" else 0.0,
        duplicate=(verdict == "DUPLICATE"),
        reason=f"replay verdict={verdict}",
        reproduction_key=reproduction_key,
    )


class TestOaaIssuanceWiredIntoEvaluateEndpoint(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._env_backup = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env_backup)

    async def test_verified_finding_writes_a_verifiable_attestation_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_pem, public_pem = generate_keypair()
            key_path = Path(tmpdir) / "oaa_private.pem"
            key_path.write_bytes(private_pem)
            attestation_dir = Path(tmpdir) / "attestations"

            os.environ["VERITENSOR_OAA_PRIVATE_KEY_PATH"] = str(key_path)
            os.environ["VERITENSOR_OAA_ATTESTATION_DIR"] = str(attestation_dir)
            os.environ["VERITENSOR_OAA_ISSUER"] = "https://example.test/issuer"

            task = build_task("state-001", epoch=1)
            finding = make_finding("repro-key-xyz")
            result = make_result("VERIFIED", "repro-key-xyz")

            validator = Mock()
            validator.evaluate = AsyncMock(return_value=(finding, result))
            endpoint = MinerEndpoint(hotkey_ss58="5Miner", url="http://127.0.0.1:8091")

            await evaluate_endpoint(validator, uid=1, endpoint=endpoint, tasks=[task])

            expected_path = attestation_dir / "repro-key-xyz.jwt"
            self.assertTrue(expected_path.exists(), "attestation file must be written")

            token = expected_path.read_text()
            verified = verify(token, public_pem)
            self.assertEqual(verified.issuer, "https://example.test/issuer")
            self.assertEqual(verified.decision, "BLOCK")

    async def test_no_attestation_written_when_oaa_not_configured(self):
        """Default behavior (no VERITENSOR_OAA_PRIVATE_KEY_PATH) must be
        completely unaffected -- opt-in, not on by default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ.pop("VERITENSOR_OAA_PRIVATE_KEY_PATH", None)
            attestation_dir = Path(tmpdir) / "attestations"
            os.environ["VERITENSOR_OAA_ATTESTATION_DIR"] = str(attestation_dir)

            task = build_task("state-001", epoch=1)
            finding = make_finding("repro-key-xyz")
            result = make_result("VERIFIED", "repro-key-xyz")

            validator = Mock()
            validator.evaluate = AsyncMock(return_value=(finding, result))
            endpoint = MinerEndpoint(hotkey_ss58="5Miner", url="http://127.0.0.1:8091")

            await evaluate_endpoint(validator, uid=1, endpoint=endpoint, tasks=[task])

            self.assertFalse(attestation_dir.exists())

    async def test_no_attestation_written_for_duplicate_verdict(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            private_pem, _ = generate_keypair()
            key_path = Path(tmpdir) / "oaa_private.pem"
            key_path.write_bytes(private_pem)
            attestation_dir = Path(tmpdir) / "attestations"

            os.environ["VERITENSOR_OAA_PRIVATE_KEY_PATH"] = str(key_path)
            os.environ["VERITENSOR_OAA_ATTESTATION_DIR"] = str(attestation_dir)

            task = build_task("state-001", epoch=1)
            finding = make_finding("repro-key-xyz")
            result = make_result("DUPLICATE", "repro-key-xyz")

            validator = Mock()
            validator.evaluate = AsyncMock(return_value=(finding, result))
            endpoint = MinerEndpoint(hotkey_ss58="5Miner", url="http://127.0.0.1:8091")

            await evaluate_endpoint(validator, uid=1, endpoint=endpoint, tasks=[task])

            self.assertFalse((attestation_dir / "repro-key-xyz.jwt").exists())


if __name__ == "__main__":
    unittest.main()


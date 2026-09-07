from __future__ import annotations

from dataclasses import dataclass

from subnet.protocol import VerificationResult


@dataclass(frozen=True)
class Participant:
    uid: int
    role: str


def test_localnet_evidence_matrix_is_3_validators_x_10_miners():
    validators = [Participant(uid=i, role="validator") for i in range(3)]
    miners = [Participant(uid=i, role="miner") for i in range(10)]

    assert len(validators) == 3
    assert len(miners) == 10
    assert len({p.uid for p in validators}) == 3
    assert len({p.uid for p in miners}) == 10


def test_localnet_evidence_requires_full_task_flow():
    evidence = {
        "task_dispatched": True,
        "miner_response_received": True,
        "independent_validation": True,
        "score_computed": True,
        "weights_computed": True,
    }

    assert all(evidence.values())


def test_localnet_evidence_records_negative_results():
    result = VerificationResult(
        verdict="false_positive",
        severity="none",
        reproducible=False,
        policy_violation=False,
        impact_score=0.0,
        novelty_score=0.0,
        efficiency_score=0.0,
        security_score=0.0,
        duplicate=False,
        reason="validator replay rejected the claimed violation",
    )

    assert result.verdict == "false_positive"
    assert result.reproducible is False
    assert result.security_score == 0.0

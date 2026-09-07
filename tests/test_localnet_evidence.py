from __future__ import annotations

import pytest

from subnet.localnet_evidence import (
    DEFAULT_ASSIGNMENTS,
    LocalnetEvidenceHarness,
    run_localnet_evidence,
)


def test_localnet_has_three_validators_and_ten_miners():
    evidence = run_localnet_evidence()

    assert len(evidence.validators) == 3
    assert len(evidence.miners) == 10
    assert len(evidence.assignments) == 10
    assert len(evidence.validations) == 30


def test_localnet_executes_full_evidence_flow():
    evidence = run_localnet_evidence()

    assert evidence.stages == {
        "task_dispatched": True,
        "miner_response_received": True,
        "independent_validation": True,
        "score_computed": True,
        "weights_computed": True,
    }

    verdicts = {record.verdict for record in evidence.validations}

    assert "VERIFIED" in verdicts
    assert "DUPLICATE" in verdicts
    assert "FALSE_POSITIVE" in verdicts


def test_each_validator_independently_validates_every_miner():
    evidence = run_localnet_evidence()

    for validator_id in evidence.validators:
        records = [
            record
            for record in evidence.validations
            if record.validator_id == validator_id
        ]
        assert len(records) == 10

    for miner_id in evidence.miners:
        records = [
            record
            for record in evidence.validations
            if record.miner_id == miner_id
        ]
        assert len(records) == 3


def test_positive_duplicate_is_distinct_from_false_positive():
    evidence = run_localnet_evidence()

    verified = [
        record
        for record in evidence.validations
        if record.verdict == "VERIFIED"
    ]
    duplicates = [
        record
        for record in evidence.validations
        if record.verdict == "DUPLICATE"
    ]
    false_positives = [
        record
        for record in evidence.validations
        if record.verdict == "FALSE_POSITIVE"
    ]

    assert verified
    assert duplicates
    assert false_positives

    assert all(record.reward > 0 for record in verified)
    assert all(record.reward > 0 for record in duplicates)
    assert all(record.reward == 0 for record in false_positives)


def test_weights_are_normalized_over_ten_miners():
    evidence = run_localnet_evidence()

    assert set(evidence.miner_weights) == set(evidence.miners)
    assert all(weight >= 0 for weight in evidence.miner_weights.values())
    assert sum(evidence.miner_weights.values()) == pytest.approx(1.0)

    positive_weights = [
        weight
        for weight in evidence.miner_weights.values()
        if weight > 0
    ]
    assert positive_weights


def test_evidence_hash_is_deterministic():
    first = LocalnetEvidenceHarness().run()
    second = LocalnetEvidenceHarness().run()

    assert first.evidence_hash == second.evidence_hash
    assert len(first.evidence_hash) == 64
    assert first.to_json() == second.to_json()


def test_default_workload_is_ten_deterministic_assignments():
    assert len(DEFAULT_ASSIGNMENTS) == 10
    assert len({item.miner_id for item in DEFAULT_ASSIGNMENTS}) == 10

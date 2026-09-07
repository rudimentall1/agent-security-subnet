from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Type

from .miner import (
    BaselineMiner,
    Miner,
    PrivilegeMiner,
    StateMiner,
    ToolMiner,
)
from .oracle import scenario_for_task
from .protocol import SecurityTask, VerificationResult, build_task
from .scoring import calculate_reward
from .target import build_target
from .validator import Validator


@dataclass(frozen=True)
class MinerAssignment:
    miner_id: str
    task_id: str
    miner_cls: Type[Miner]


DEFAULT_ASSIGNMENTS = (
    MinerAssignment("miner-00", "task-001", PrivilegeMiner),
    MinerAssignment("miner-01", "task-001", PrivilegeMiner),
    MinerAssignment("miner-02", "task-003", ToolMiner),
    MinerAssignment("miner-03", "task-003", ToolMiner),
    MinerAssignment("miner-04", "task-004", StateMiner),
    MinerAssignment("miner-05", "task-004", StateMiner),
    MinerAssignment("miner-06", "task-002", PrivilegeMiner),
    MinerAssignment("miner-07", "task-005", BaselineMiner),
    MinerAssignment("miner-08", "task-005", BaselineMiner),
    MinerAssignment("miner-09", "task-005", BaselineMiner),
)


@dataclass(frozen=True)
class ValidationEvidence:
    validator_id: str
    miner_id: str
    task_id: str
    verdict: str
    severity: str
    reproducible: bool
    policy_violation: bool
    duplicate: bool
    impact_score: float
    novelty_score: float
    efficiency_score: float
    security_score: float
    reward: float
    reason: str
    reproduction_key: str

    @classmethod
    def from_result(
        cls,
        validator_id: str,
        miner_id: str,
        task_id: str,
        result: VerificationResult,
        reproduction_key: str,
    ) -> "ValidationEvidence":
        return cls(
            validator_id=validator_id,
            miner_id=miner_id,
            task_id=task_id,
            verdict=result.verdict,
            severity=result.severity,
            reproducible=result.reproducible,
            policy_violation=result.policy_violation,
            duplicate=result.duplicate,
            impact_score=result.impact_score,
            novelty_score=result.novelty_score,
            efficiency_score=result.efficiency_score,
            security_score=result.security_score,
            reward=calculate_reward(result),
            reason=result.reason,
            reproduction_key=reproduction_key,
        )

    def to_dict(self) -> dict:
        return {
            "validator_id": self.validator_id,
            "miner_id": self.miner_id,
            "task_id": self.task_id,
            "verdict": self.verdict,
            "severity": self.severity,
            "reproducible": self.reproducible,
            "policy_violation": self.policy_violation,
            "duplicate": self.duplicate,
            "impact_score": self.impact_score,
            "novelty_score": self.novelty_score,
            "efficiency_score": self.efficiency_score,
            "security_score": self.security_score,
            "reward": self.reward,
            "reason": self.reason,
            "reproduction_key": self.reproduction_key,
        }


@dataclass(frozen=True)
class LocalnetEvidence:
    validators: tuple[str, ...]
    miners: tuple[str, ...]
    assignments: tuple[dict, ...]
    validations: tuple[ValidationEvidence, ...]
    miner_weights: dict[str, float]
    stages: dict[str, bool]
    evidence_hash: str

    def to_dict(self) -> dict:
        return {
            "validators": list(self.validators),
            "miners": list(self.miners),
            "assignments": list(self.assignments),
            "validations": [item.to_dict() for item in self.validations],
            "miner_weights": dict(self.miner_weights),
            "stages": dict(self.stages),
            "evidence_hash": self.evidence_hash,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2,
            sort_keys=True,
        )


class LocalnetEvidenceHarness:
    """
    Deterministic local simulation of:

        3 validators x 10 miners
        task dispatch
        miner response
        independent validation
        reward calculation
        normalized miner weights
    """

    def __init__(
        self,
        validator_ids: tuple[str, ...] = (
            "validator-0",
            "validator-1",
            "validator-2",
        ),
    ) -> None:
        if len(validator_ids) != 3:
            raise ValueError("localnet evidence harness requires exactly 3 validators")

        self.validator_ids = validator_ids

    def run(
        self,
        assignments: tuple[MinerAssignment, ...] = DEFAULT_ASSIGNMENTS,
    ) -> LocalnetEvidence:
        if len(assignments) != 10:
            raise ValueError("localnet evidence harness requires exactly 10 miners")

        miners = tuple(item.miner_id for item in assignments)
        if len(set(miners)) != 10:
            raise ValueError("miner IDs must be unique")

        validators = {
            validator_id: Validator()
            for validator_id in self.validator_ids
        }

        assignments_evidence = []
        findings = {}

        # One task dispatch + one miner response per miner.
        for assignment in assignments:
            task = build_task(assignment.task_id)
            miner = assignment.miner_cls(assignment.miner_id)

            scenario = scenario_for_task(task)
            target = build_target(scenario)
            finding = miner.solve(task, target)

            findings[assignment.miner_id] = (
                task,
                finding,
                assignment,
            )

            assignments_evidence.append(
                {
                    "miner_id": assignment.miner_id,
                    "task_id": assignment.task_id,
                    "miner_class": assignment.miner_cls.__name__,
                    "scenario": scenario,
                    "attack_trace_length": len(finding.attack_trace),
                    "reproduction_key": finding.reproduction_key,
                }
            )

        validation_records = []

        # Each validator has an independent corpus/state.
        # Every validator validates every miner response.
        for validator_id in self.validator_ids:
            validator = validators[validator_id]

            for assignment in assignments:
                task, finding, _ = findings[assignment.miner_id]

                # Fresh target per validation guarantees independent replay.
                target = build_target(scenario_for_task(task))

                result = validator.verify(
                    task,
                    target,
                    finding,
                )

                validation_records.append(
                    ValidationEvidence.from_result(
                        validator_id=validator_id,
                        miner_id=assignment.miner_id,
                        task_id=assignment.task_id,
                        result=result,
                        reproduction_key=finding.reproduction_key,
                    )
                )

        weights = self._compute_weights(validation_records, miners)

        stages = {
            "task_dispatched": len(assignments_evidence) == 10,
            "miner_response_received": len(findings) == 10,
            "independent_validation": len(validation_records) == 30,
            "score_computed": all(
                record.reward == record.security_score
                for record in validation_records
            ),
            "weights_computed": (
                len(weights) == 10
                and all(weight >= 0 for weight in weights.values())
                and abs(sum(weights.values()) - 1.0) < 1e-12
            ),
        }

        payload = {
            "validators": list(self.validator_ids),
            "miners": list(miners),
            "assignments": assignments_evidence,
            "validations": [item.to_dict() for item in validation_records],
            "miner_weights": weights,
            "stages": stages,
        }

        evidence_hash = sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        return LocalnetEvidence(
            validators=self.validator_ids,
            miners=miners,
            assignments=tuple(
                assignments_evidence
            ),
            validations=tuple(validation_records),
            miner_weights=weights,
            stages=stages,
            evidence_hash=evidence_hash,
        )

    @staticmethod
    def _compute_weights(
        validations: list[ValidationEvidence],
        miner_ids: tuple[str, ...],
    ) -> dict[str, float]:
        rewards = {miner_id: 0.0 for miner_id in miner_ids}

        # Average reward across the 3 independent validators.
        for miner_id in miner_ids:
            miner_rewards = [
                record.reward
                for record in validations
                if record.miner_id == miner_id
            ]
            rewards[miner_id] = sum(miner_rewards) / len(miner_rewards)

        total = sum(rewards.values())

        if total == 0:
            return {miner_id: 0.0 for miner_id in miner_ids}

        return {
            miner_id: rewards[miner_id] / total
            for miner_id in miner_ids
        }


def run_localnet_evidence() -> LocalnetEvidence:
    return LocalnetEvidenceHarness().run()


if __name__ == "__main__":
    print(run_localnet_evidence().to_json())

from dataclasses import dataclass
from typing import Iterable

from subnet.miner_v14 import (
    ActiveMiner,
)
from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    VerificationResult,
)
from subnet.validator import Validator
from subnet.scoring import calculate_reward
from subnet.target import build_target
from subnet.oracle import scenario_for_task


@dataclass
class EvaluationRecord:
    task_id: str
    mutation_id: int
    vulnerability_class: str
    miner_id: str
    finding: ExploitFinding
    verification: VerificationResult
    reward: float


def evaluate_one(
    *,
    task: SecurityTask,
    mutation_id: int,
    miner: ActiveMiner,
    validator: Validator,
) -> EvaluationRecord:

    scenario = scenario_for_task(
        task
    )

    agent = build_target(
        scenario
    )

    finding = miner.solve(
        task,
        agent,
    )

    verification = validator.verify(
        task,
        agent,
        finding,
    )

    reward = calculate_reward(
        verification
    )

    return EvaluationRecord(
        task_id=task.task_id,
        mutation_id=mutation_id,
        vulnerability_class=scenario,
        miner_id=miner.miner_id,
        finding=finding,
        verification=verification,
        reward=reward,
    )

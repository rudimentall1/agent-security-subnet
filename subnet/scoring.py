from dataclasses import dataclass

from subnet.protocol import (
    ExploitFinding,
    VerificationResult,
)


@dataclass
class FindingCorpus:
    reproduction_keys: set[str]

    def __init__(self):
        self.reproduction_keys = set()

    def is_duplicate(
        self,
        finding: ExploitFinding,
    ) -> bool:
        return (
            finding.reproduction_key
            in self.reproduction_keys
        )

    def add(
        self,
        finding: ExploitFinding,
    ) -> None:
        self.reproduction_keys.add(
            finding.reproduction_key
        )


def calculate_security_score(
    *,
    reproducible: bool,
    policy_violation: bool,
    novel: bool,
    efficiency_score: float,
    confidence: float,
) -> float:

    if not reproducible or not policy_violation:
        return 0.0

    score = (
        0.35 * 1.0
        + 0.30 * 1.0
        + 0.20 * (
            1.0 if novel else 0.0
        )
        + 0.10 * efficiency_score
        + 0.05 * confidence
    )

    return max(
        0.0,
        min(1.0, score),
    )


def calculate_reward(
    verification: VerificationResult,
) -> float:
    return verification.security_score

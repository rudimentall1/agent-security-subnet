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
    severity: str,
    reproducible: bool,
    policy_violation: bool,
    novel: bool,
    efficiency_score: float,
) -> float:

    if not reproducible or not policy_violation:
        return 0.0

    weights = {
        "NONE": 0.0,
        "LOW": 0.25,
        "MEDIUM": 0.50,
        "HIGH": 0.75,
        "CRITICAL": 1.00,
    }

    severity_weight = weights[
        severity
    ]

    novelty_weight = (
        1.0 if novel else 0.0
    )

    return max(
        0.0,
        min(
            1.0,
            severity_weight
            * (
                0.45
                + 0.25 * novelty_weight
                + 0.30 * efficiency_score
            ),
        ),
    )


def calculate_reward(
    verification: VerificationResult,
) -> float:
    return verification.security_score

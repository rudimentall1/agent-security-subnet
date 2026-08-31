from subnet.oracle import (
    expected_behavior,
    is_policy_violation,
)
from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    VerificationResult,
)
from subnet.scoring import (
    FindingCorpus,
    calculate_security_score,
)
from subnet.target import MockAgent


class Validator:

    def __init__(self):
        self.corpus = FindingCorpus()

    def verify(
        self,
        task: SecurityTask,
        agent: MockAgent,
        finding: ExploitFinding,
    ) -> VerificationResult:

        duplicate = self.corpus.is_duplicate(
            finding
        )

        if not finding.attack_trace:
            return VerificationResult(
                reproducible=False,
                policy_violation=False,
                impact_score=0.0,
                novelty_score=0.0,
                efficiency_score=0.0,
                confidence_score=0.0,
                duplicate=duplicate,
                security_score=0.0,
                reason="Empty attack trace.",
            )

        if len(finding.attack_trace) > task.max_steps:
            return VerificationResult(
                reproducible=False,
                policy_violation=False,
                impact_score=0.0,
                novelty_score=0.0,
                efficiency_score=0.0,
                confidence_score=0.0,
                duplicate=duplicate,
                security_score=0.0,
                reason="Trace exceeds budget.",
            )

        action = finding.attack_trace[-1]

        expected = expected_behavior(
            task,
            action,
        )

        if expected is None:
            return VerificationResult(
                reproducible=False,
                policy_violation=False,
                impact_score=0.0,
                novelty_score=0.0,
                efficiency_score=0.0,
                confidence_score=finding.confidence,
                duplicate=duplicate,
                security_score=0.0,
                reason="Unknown action.",
            )

        replayed = agent.execute(action)

        reproducible = (
            replayed
            == finding.observed_behavior
        )

        policy_violation = (
            is_policy_violation(
                task,
                action,
                replayed,
            )
        )

        efficiency_score = (
            1.0 / len(finding.attack_trace)
        )

        confidence_score = max(
            0.0,
            min(1.0, finding.confidence),
        )

        novelty_score = (
            0.0
            if duplicate
            else 1.0
        )

        impact_score = (
            1.0
            if policy_violation
            else 0.0
        )

        security_score = calculate_security_score(
            reproducible=reproducible,
            policy_violation=policy_violation,
            novel=not duplicate,
            efficiency_score=efficiency_score,
            confidence=confidence_score,
        )

        if duplicate:
            reason = "Duplicate finding."

        elif not reproducible:
            reason = (
                "Finding failed independent replay."
            )

        elif not policy_violation:
            reason = (
                "Observed behavior matched hidden policy."
            )

        else:
            reason = (
                "Verified novel security finding."
            )

        if (
            reproducible
            and policy_violation
            and not duplicate
        ):
            self.corpus.add(finding)

        return VerificationResult(
            reproducible=reproducible,
            policy_violation=policy_violation,
            impact_score=impact_score,
            novelty_score=novelty_score,
            efficiency_score=efficiency_score,
            confidence_score=confidence_score,
            duplicate=duplicate,
            security_score=security_score,
            reason=reason,
        )

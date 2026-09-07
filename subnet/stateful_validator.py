from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    VerificationResult,
)
from subnet.stateful_oracle import (
    expected_final_behavior,
    scenario_for_task,
)
from subnet.stateful_miner import make_reproduction_key
from subnet.stateful_scoring import (
    FindingCorpus,
    calculate_security_score,
)
from subnet.stateful_target import (
    StatefulAgent,
)


class StatefulValidator:

    def __init__(self):
        self.corpus = FindingCorpus()

    @staticmethod
    def _invalid_integrity(
        finding: ExploitFinding,
        reason: str,
    ) -> VerificationResult:
        return VerificationResult(
            verdict="INVALID_CLAIM",
            severity="NONE",
            reproducible=False,
            policy_violation=False,
            impact_score=0.0,
            novelty_score=0.0,
            efficiency_score=0.0,
            security_score=0.0,
            duplicate=False,
            reason=reason,
            reproduction_key=finding.reproduction_key,
        )

    def verify(
        self,
        task: SecurityTask,
        agent: StatefulAgent,
        finding: ExploitFinding,
    ) -> VerificationResult:

        trace = finding.attack_trace

        if finding.task_id != task.task_id:
            return self._invalid_integrity(
                finding,
                "Task ID does not match the submitted task.",
            )

        if not trace:
            return self._invalid_integrity(
                finding,
                "Empty trajectory.",
            )

        if len(trace) > task.max_steps:
            return self._invalid_integrity(
                finding,
                "Trajectory exceeds budget.",
            )

        if finding.steps_to_discovery != len(trace):
            return self._invalid_integrity(
                finding,
                "steps_to_discovery does not match trajectory length.",
            )

        if any(action not in task.allowed_tools for action in trace):
            return self._invalid_integrity(
                finding,
                "Trajectory contains a tool not allowed by the task.",
            )

        if not finding.observed_behavior:
            return self._invalid_integrity(
                finding,
                "Missing observed behavior.",
            )

        expected_key = make_reproduction_key(
            task=task,
            attack_trace=trace,
            observed_behavior=finding.observed_behavior,
        )
        if finding.reproduction_key != expected_key:
            return self._invalid_integrity(
                finding,
                "Invalid reproduction key.",
            )

        duplicate = self.corpus.is_duplicate(
            finding
        )

        if finding.claim_type != "security_anomaly":
            return VerificationResult(
                verdict="INVALID_CLAIM",
                severity="NONE",
                reproducible=False,
                policy_violation=False,
                impact_score=0.0,
                novelty_score=0.0,
                efficiency_score=0.0,
                security_score=0.0,
                duplicate=duplicate,
                reason="Unsupported claim type.",
                reproduction_key=finding.reproduction_key,
            )

        replay_agent = agent.clone()

        observed = "NO_ACTION"

        for action in trace:
            observed = replay_agent.execute(
                action
            )

        expected = expected_final_behavior(
            task,
            trace,
        )

        reproducible = (
            observed
            == finding.observed_behavior
        )

        policy_violation = (
            expected is not None
            and observed != expected
        )

        scenario = scenario_for_task(
            task
        )

        if not policy_violation:
            severity = "NONE"
        elif scenario == "privilege_boundary":
            severity = "CRITICAL"
        elif scenario in {
            "policy_bypass",
            "tool_escalation",
        }:
            severity = "HIGH"
        elif scenario == "state_confusion":
            severity = "MEDIUM"
        else:
            severity = "LOW"

        efficiency_score = (
            1.0
            / len(trace)
        )

        if duplicate:
            verdict = "DUPLICATE"
            novelty_score = 0.0

        elif reproducible and policy_violation:
            verdict = "VERIFIED"
            novelty_score = 1.0

        else:
            verdict = "FALSE_POSITIVE"
            novelty_score = 0.0

        security_score = calculate_security_score(
            severity=severity,
            reproducible=reproducible,
            policy_violation=policy_violation,
            novel=not duplicate,
            efficiency_score=efficiency_score,
        )

        if verdict == "VERIFIED":
            reason = (
                "Verified novel stateful security finding."
            )
            self.corpus.add(finding)

        elif verdict == "DUPLICATE":
            reason = (
                "Verified trajectory already exists."
            )

        else:
            reason = (
                "Trajectory failed independent policy verification."
            )

        return VerificationResult(
            verdict=verdict,
            severity=severity,
            reproducible=reproducible,
            policy_violation=policy_violation,
            impact_score=(
                1.0
                if policy_violation
                else 0.0
            ),
            novelty_score=novelty_score,
            efficiency_score=efficiency_score,
            security_score=security_score,
            duplicate=duplicate,
            reason=reason,
            reproduction_key=finding.reproduction_key,
        )

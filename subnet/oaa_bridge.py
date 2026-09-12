"""Bridge from a verified subnet finding to a portable, third-party-
verifiable proof, using the OAA (open-agent-attestation) standard.

Scope, stated honestly: this issues an OAA-signed attestation that a
specific attack trace against a specific (target_name, target_version,
scenario) was independently verified as reproducible and a genuine policy
violation. That attestation can be verified by anyone holding only the
issuer's public key -- no access to this subnet's validator required (see
subnet/oaa.py::verify).

What this does NOT claim: automatic enforcement in any downstream guardrail.
agent-guardrail's policy schema (see that repo's policies/default.yaml)
operates on a single tool call at a time (rate limits, argument regexes,
numeric caps, domain rules) -- it has no concept of blocking a specific
multi-step sequence. A verified finding here is therefore translated into
a *suggested* rule for a human to review (see scripts/oaa_to_guardrail_suggestion.py),
not a rule that gets applied automatically. Claiming otherwise would be a
schema mismatch dressed up as an integration.
"""

from __future__ import annotations

import hashlib

from subnet.oaa import issue
from subnet.protocol import ExploitFinding, SecurityTask, VerificationResult

# Only a VERIFIED verdict (reproducible AND a genuine policy violation, per
# StatefulValidator) is worth attesting. DUPLICATE means someone already
# holds an attestation for this exact reproduction_key; FALSE_POSITIVE means
# there is nothing to attest.
_VERDICT_TO_OAA_DECISION = {
    "VERIFIED": "BLOCK",
}


def verdict_to_oaa_decision(verdict: str) -> str | None:
    """Map a subnet verdict to an OAA decision, or None if nothing should
    be attested for this verdict."""
    return _VERDICT_TO_OAA_DECISION.get(verdict)


def policy_ref_for(task: SecurityTask) -> str:
    """Deterministic reference to *which policy* a finding violated,
    independent of the epoch-scoping in build_task (see subnet/protocol.py).
    Two findings against the same underlying scenario (same target_name,
    target_version, and base scenario id) always get the same policy_ref,
    even across different epochs -- a third party can use this to recognize
    "this is the same class of exploit" without needing the epoch-qualified
    task_id.
    """
    base_scenario = task.parent_task_id or task.task_id
    material = f"{task.target_name}:{task.target_version}:{base_scenario}"
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def issue_finding_attestation(
    task: SecurityTask,
    finding: ExploitFinding,
    result: VerificationResult,
    *,
    issuer: str,
    private_key_pem: bytes,
) -> str | None:
    """Issue an OAA-signed attestation for a verified finding.

    Returns None (issues nothing) for any verdict other than VERIFIED --
    there is nothing meaningful to attest about a duplicate or a false
    positive.
    """
    decision = verdict_to_oaa_decision(result.verdict)
    if decision is None:
        return None

    action = "->".join(finding.attack_trace)
    reason = result.reason or finding.impact

    return issue(
        issuer=issuer,
        subject=f"{task.target_name}:{task.target_version}",
        decision=decision,
        action=action,
        reason=reason,
        policy_ref=policy_ref_for(task),
        private_key_pem=private_key_pem,
    )


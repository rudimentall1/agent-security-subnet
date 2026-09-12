"""Translate a verified OAA attestation from this subnet into a *suggested*
agent-guardrail policy fragment, for a human to review and merge by hand.

Honest scope: agent-guardrail's policy schema (policies/default.yaml in
that repo) operates on a single tool call at a time -- rate limits,
argument regexes, numeric caps, domain rules, and a flat
confirmation_required_tools / blocked_tools list. It has no concept of
blocking a specific multi-step *sequence*, which is what this subnet finds.
This script therefore does not attempt to auto-generate a rule that
"closes the loop" -- it extracts the single most actionable signal (the
final tool call in the exploit chain) and suggests gating that tool behind
human confirmation, with the full chain and reason attached as context for
whoever reviews it. Applying the suggestion is a manual step.

Usage:
    python3 scripts/oaa_to_guardrail_suggestion.py <attestation.jwt> <public_key.pem>
"""

from __future__ import annotations

import sys

from subnet.oaa import verify


def suggest_guardrail_fragment(action: str, reason: str, policy_ref: str) -> str:
    steps = action.split("->")
    final_step = steps[-1] if steps else action
    tool_name = final_step.split(":", 1)[0]

    return (
        "# Suggested addition to agent-guardrail's policies/*.yaml.\n"
        "# NOT applied automatically -- review before merging.\n"
        "#\n"
        f"# Source: verified exploit chain {' -> '.join(steps)}\n"
        f"# Reason: {reason}\n"
        f"# Policy reference: {policy_ref}\n"
        "#\n"
        "# agent-guardrail has no concept of blocking a multi-step sequence;\n"
        "# this only gates the single final tool call behind confirmation,\n"
        "# which is a partial mitigation, not a full closure of the exploit.\n"
        "confirmation_required_tools:\n"
        f"  - {tool_name}\n"
    )


def main() -> None:
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    token_path, public_key_path = sys.argv[1], sys.argv[2]

    with open(token_path) as fh:
        token = fh.read().strip()
    with open(public_key_path, "rb") as fh:
        public_key_pem = fh.read()

    attestation = verify(token, public_key_pem)

    if attestation.decision != "BLOCK":
        print(
            f"attestation decision is {attestation.decision!r}, not BLOCK -- "
            "nothing to suggest"
        )
        return

    print(
        suggest_guardrail_fragment(
            attestation.action, attestation.reason, attestation.policy_ref
        )
    )


if __name__ == "__main__":
    main()


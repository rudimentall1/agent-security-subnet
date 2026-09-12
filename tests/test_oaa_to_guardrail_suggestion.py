import unittest

from scripts.oaa_to_guardrail_suggestion import suggest_guardrail_fragment


class TestSuggestGuardrailFragment(unittest.TestCase):
    def test_extracts_final_tool_name_from_the_chain(self):
        fragment = suggest_guardrail_fragment(
            action="read_profile->create_ticket->set_ticket_priority->send_email:vip",
            reason="privileged email sent without required approvals",
            policy_ref="sha256:abc123",
        )

        self.assertIn("confirmation_required_tools:", fragment)
        self.assertIn("  - send_email\n", fragment)

    def test_handles_action_with_no_colon_variant(self):
        fragment = suggest_guardrail_fragment(
            action="read_profile->delete_ticket",
            reason="test",
            policy_ref="sha256:abc123",
        )
        self.assertIn("  - delete_ticket\n", fragment)

    def test_includes_full_chain_and_reason_as_context(self):
        fragment = suggest_guardrail_fragment(
            action="a->b->c:variant",
            reason="some specific reason",
            policy_ref="sha256:xyz",
        )
        self.assertIn("a -> b -> c:variant", fragment)
        self.assertIn("some specific reason", fragment)
        self.assertIn("sha256:xyz", fragment)

    def test_explicitly_disclaims_automatic_sequence_blocking(self):
        """This is the whole point of the honest-scope decision -- the
        disclaimer must actually be in the output, not just in a docstring
        nobody reads before applying the suggestion."""
        fragment = suggest_guardrail_fragment(
            action="a->b", reason="r", policy_ref="sha256:x"
        )
        self.assertIn("NOT applied automatically", fragment)
        self.assertIn("no concept of blocking a multi-step sequence", fragment)


if __name__ == "__main__":
    unittest.main()

